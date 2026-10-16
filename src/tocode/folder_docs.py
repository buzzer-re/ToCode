"""Top-level documents of a folder export."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__
from .links.analyze import FolderLinks
from .links.inventory import Inventory
from .metadata import write_json, write_text_atomic
from .progress import Progress


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def write_master_documents(
    master: Path,
    inventory: Inventory,
    links: FolderLinks,
    jobs: list[Any],
    options: Any,
    *,
    progress: Progress | None,
    link_result: Any = None,
) -> None:
    master.mkdir(parents=True, exist_ok=True)
    job_by_path = {job.relpath: job for job in jobs}
    entries = []
    for entry in inventory.entries:
        row = entry.to_json()
        job = job_by_path.get(entry.relpath)
        if job is not None:
            row["export_dir"] = _rel(job.export_dir, master)
            row["status"] = job.status
        entries.append(row)
    write_json(
        master / "inventory.json",
        {
            "input": str(inventory.root),
            "arch": inventory.arch,
            "file_count": len(inventory.entries),
            "binary_count": sum(1 for entry in inventory.entries if entry.job),
            "skipped_dirs": inventory.skipped_dirs,
            "files": entries,
        },
    )
    edges = [edge.to_json() for edge in links.resolution.edges]
    for row in edges:
        target = row.get("to")
        job = job_by_path.get(target) if target else None
        row["to_export_dir"] = _rel(job.export_dir, master) if job else None
    loaded_by: dict[str, list[str]] = {}
    for edge in links.resolution.edges:
        if edge.target and edge.status == "in_folder":
            loaded_by.setdefault(edge.target, []).append(edge.source)
    write_json(
        master / "dependency-graph.json",
        {
            "schema_version": 1,
            "roots": inventory.roots,
            "chains": links.resolution.chains,
            "export_order": [job.relpath for job in jobs],
            "cycles": links.resolution.cycles,
            "edge_status": dict(
                sorted(Counter(edge.status for edge in links.resolution.edges).items())
            ),
            "loaded_by": {
                key: sorted(set(value)) for key, value in sorted(loaded_by.items())
            },
            "edges": edges,
        },
    )
    statuses = Counter(job.status.split(":", 1)[0] for job in jobs)
    project: dict[str, object] = {
        "kind": "folder",
        "tocode_version": __version__,
        "input": str(inventory.root),
        "root_dir": str(master),
        "arch": inventory.arch,
        "options": {
            "only": list(options.only),
            "exclude": list(options.exclude),
            "include_framework": options.include_framework,
            "native": options.native,
            "managed": options.managed,
            "backend": options.native_options.backend,
            "tree": options.native_options.tree,
            "entropy": options.native_options.entropy,
        },
        "binary_count": sum(1 for entry in inventory.entries if entry.job),
        "job_status": dict(sorted(statuses.items())),
        "binaries": [job.to_json(master) for job in jobs],
        "inventory": "inventory.json",
        "dependency_graph": "dependency-graph.json",
        "mappings": "mappings.json",
        "agents": "AGENTS.md",
        "log": "tocode.log",
    }
    write_json(master / "project.json", project)
    manifest: dict[str, object] = dict(project)
    if link_result is not None:
        manifest["links"] = {
            "bound_in_folder": link_result.bound,
            "mapped_to_function": link_result.mapped,
            "annotated_source_lines": link_result.annotated_lines,
        }
        manifest["address_spaces"] = link_result.address_spaces
    write_json(master / "export-manifest.json", manifest)
    write_text_atomic(
        master / "AGENTS.md", build_folder_agents(inventory, links, jobs, master)
    )
    write_text_atomic(master / "CLAUDE.md", "@./AGENTS.md\n")
    if progress is not None:
        progress.file_log(f"Wrote folder metadata to {master}")


def build_folder_agents(
    inventory: Inventory, links: FolderLinks, jobs: list[Any], master: Path
) -> str:
    done = [job for job in jobs if job.status == "done"]
    other = [job for job in jobs if job.status != "done"]
    lines = [
        "# AGENTS",
        "",
        f"You are working inside a ToCode folder export of `{inventory.root.name}`: every binary "
        "of the folder decompiled into its own export, plus the links between them.",
        "Treat the recovered source, assembly, metadata, and link tables as evidence for reverse engineering.",
        "",
        "## Mission",
        "",
        "Reverse the application, answer user questions, or serve as an oracle/helper to the user regarding this recovered code.",
        "Write a report only when the user asks for one; otherwise keep findings focused on the question or task at hand.",
        "Do not refactor or modify the generated export unless the user explicitly asks for edits.",
        "",
        "## What a link is",
        "",
        "Links come only from the binaries' own load and import tables, resolved with the platform "
        "loader's rules (Mach-O two-level namespace, `@rpath`/`@loader_path`; ELF `DT_NEEDED`, "
        "`RPATH`/`RUNPATH`, symbol versions; PE import/delay-import tables, forwarders; .NET "
        "AssemblyRef/MemberRef signatures and P/Invoke). Nothing is matched by similarity. "
        "Strings passed to `dlopen`/`LoadLibrary` and Objective-C message sends are not links.",
        "",
        "## Files",
        "",
        "- `<path>/<file>/`: one export per binary, mirroring the folder (the directory is named after the file). Each has its own `AGENTS.md`.",
        "- `project.json` and `export-manifest.json`: inputs, options, and the status of every binary's export.",
        "- `inventory.json`: every file of the folder with its kind, architecture(s), SHA-256, export directory, and status (filtered, runtime library, duplicate, failed, ...).",
        "- `dependency-graph.json`: which file loads which (`edges`, with the loader rule in `via`), the load chain of each executable, `loaded_by`, export order, and cycles.",
        "- `mappings.json`: every imported symbol of every binary: where it binds (`target`, `export`, `target_va`/`target_token`), the defining function's source file and line range in the target's export (`target_function`), and the importer functions that call it (`call_sites`). `address_spaces` records how link-time addresses were matched to each export.",
        "- Inside each export: `imports.json` has `libraries` (resolved library edges) and a `link` per import; `functions.json` has `import_links` on callers and `imported_by` on the functions other files call; `exports.json` has `imported_by_count`. Calls are annotated in `src/raw` with `/* tocode-link: symbol -> file:start-end */` (or in the function's `/* metadata:` header when the call line could not be identified). Annotations never add lines, so all line numbers stay valid.",
        "- `tocode.log`: the folder run, with each binary's export log mirrored.",
        "",
        "## Working Style",
        "",
        "- Start with `dependency-graph.json` to see the architecture, then the main executable's export.",
        "- Follow a call across files with `mappings.json` or the `tocode-link` comments instead of searching by name.",
        "- A link whose `target_status` is not `decompiled` (filtered, runtime library, failed) still names the file and address; export it with `--only` to read it.",
        "- Cite file paths, function names, addresses, and line numbers for every major claim.",
        "- With the `tocode` MCP server, `open` this folder and address each binary as "
        '`session="<relative path>"`; `sync` updates that binary\'s export and these links.',
        "",
        "## Binaries",
        "",
    ]
    for job in done[:200]:
        rel = _rel(job.export_dir, master)
        lines.append(
            f"- `{job.relpath}` -> `{rel}/` ({job.function_count} functions, {job.backend})"
        )
    if len(done) > 200:
        lines.append(f"- ... {len(done) - 200} more in `project.json`")
    if other:
        lines.extend(["", "Not exported in this run:", ""])
        for job in other[:100]:
            lines.append(f"- `{job.relpath}`: {job.status}")
        if len(other) > 100:
            lines.append(f"- ... {len(other) - 100} more in `project.json`")
    lines.append("")
    return "\n".join(lines)
