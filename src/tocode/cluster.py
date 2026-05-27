from __future__ import annotations

from collections import Counter, deque

from .naming import SHARED_CLUSTER_ID
from .schema import Cluster


def describe_imports(names: list[str]) -> str:
    if not names:
        return "General functions"
    return ", ".join(name for name, _count in Counter(names).most_common(3))


def cluster_routines(
    *,
    addresses: list[int],
    roots: list[int],
    callees: dict[int, list[int]],
    callers: dict[int, list[int]],
    thunks: set[int],
) -> list[Cluster]:
    ordered = [address for address in addresses if address not in thunks]
    allowed = set(ordered)
    if not allowed:
        return []

    components = _scc(ordered, allowed, callees, callers)
    component_for: dict[int, int] = {}
    for index, component in enumerate(components):
        for address in component:
            component_for[address] = index

    preds: list[set[int]] = [set() for _ in components]
    succs: list[set[int]] = [set() for _ in components]
    for address in ordered:
        source = component_for[address]
        for target in callees.get(address, []):
            if target not in allowed:
                continue
            dest = component_for[target]
            if dest != source:
                succs[source].add(dest)
                preds[dest].add(source)

    labels: dict[int, int] = {}
    shared_components: set[int] = set()
    indegree = [len(items) for items in preds]
    ready = deque(index for index, degree in enumerate(indegree) if degree == 0)
    while ready:
        index = ready.popleft()
        upstream = preds[index]
        if not upstream:
            labels[index] = index
        else:
            parent_labels = {labels[parent] for parent in upstream}
            if len(parent_labels) == 1:
                labels[index] = next(iter(parent_labels))
            else:
                labels[index] = index
                shared_components.add(index)
        for successor in succs[index]:
            indegree[successor] -= 1
            if indegree[successor] == 0:
                ready.append(successor)

    buckets: dict[int, list[int]] = {}
    shared_members: list[int] = []
    for index, component in enumerate(components):
        if index in shared_components:
            shared_members.extend(component)
        else:
            buckets.setdefault(labels[index], []).extend(component)

    root_set = set(roots)
    clusters: list[Cluster] = []
    for label, members in buckets.items():
        member_set = set(members)
        root = next((candidate for candidate in roots if candidate in member_set), components[label][0])
        clusters.append(
            Cluster(
                root=root,
                label=f"cluster_{root:#x}",
                summary="",
                members=_preorder(root, member_set, callees),
            )
        )

    if shared_members:
        shared_members.sort()
        clusters.append(
            Cluster(
                root=SHARED_CLUSTER_ID,
                label="utils",
                summary="Shared utility functions",
                members=shared_members,
            )
        )

    clusters.sort(key=lambda c: (0 if c.root in root_set else 1, -len(c.members)))
    return clusters


def _scc(
    ordered: list[int],
    allowed: set[int],
    callees: dict[int, list[int]],
    callers: dict[int, list[int]],
) -> list[list[int]]:
    visited: set[int] = set()
    finished: list[int] = []

    for start in ordered:
        if start in visited:
            continue
        stack: list[tuple[int, bool]] = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finished.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            for child in reversed(callees.get(node, [])):
                if child in allowed and child not in visited:
                    stack.append((child, False))

    visited.clear()
    groups: list[list[int]] = []
    for start in reversed(finished):
        if start in visited:
            continue
        group: list[int] = []
        stack = [start]
        visited.add(start)
        while stack:
            node = stack.pop()
            group.append(node)
            for parent in callers.get(node, []):
                if parent in allowed and parent not in visited:
                    visited.add(parent)
                    stack.append(parent)
        groups.append(group)
    return groups


def _preorder(root: int, members: set[int], callees: dict[int, list[int]]) -> list[int]:
    output: list[int] = []
    seen: set[int] = set()
    stack = [root]
    while stack:
        address = stack.pop()
        if address not in members or address in seen:
            continue
        seen.add(address)
        output.append(address)
        for child in reversed(callees.get(address, [])):
            if child in members and child not in seen:
                stack.append(child)
    for address in members:
        if address not in seen:
            output.append(address)
    return output
