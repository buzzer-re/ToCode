from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import sys
from typing import Any, Iterator, Protocol

_tqdm_module: Any
try:  # pragma: no cover - dependency presence is covered by CLI/export tests.
    import tqdm as _loaded_tqdm_module
except ImportError:  # pragma: no cover
    _tqdm_module = None
else:
    _tqdm_module = _loaded_tqdm_module

_tqdm: Any = getattr(_tqdm_module, "tqdm", None)


class _NullProgress:
    def update(self, _value: int = 1) -> None:
        return

    def close(self) -> None:
        return


class ProgressBar(Protocol):
    def update(self, value: int = 1) -> object: ...

    def close(self) -> None: ...


class Progress:
    def __init__(self, *, enabled: bool = True, log_path: Path | None = None) -> None:
        self.enabled = enabled
        self.log_path = log_path

    def set_log_path(self, path: Path) -> None:
        self.log_path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, message: str) -> None:
        if self.enabled:
            writer = getattr(_tqdm, "write", None)
            if callable(writer):
                # Prints above any active progress bars instead of through them.
                writer(message, file=sys.stderr)
            else:
                print(message, file=sys.stderr)
        self.file_log(message)

    def new_bar(self, **kwargs: Any) -> Any:
        """A tqdm bar the caller updates and closes itself (or a no-op)."""
        tqdm_factory: Any = _tqdm
        if not self.enabled or tqdm_factory is None:
            return None
        kwargs.setdefault("dynamic_ncols", True)
        kwargs.setdefault("leave", False)
        kwargs.setdefault("file", sys.stderr)
        return tqdm_factory(**kwargs)

    def file_log(self, message: str) -> None:
        if self.log_path is not None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().isoformat(timespec="seconds")
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"{timestamp} {message}\n")

    @contextmanager
    def bar(
        self, *, total: int, desc: str, unit: str, unit_scale: bool = False
    ) -> Iterator[ProgressBar]:
        tqdm_factory: Any = _tqdm
        if not self.enabled or tqdm_factory is None:
            yield _NullProgress()
            return
        bar = tqdm_factory(
            total=total,
            desc=desc,
            unit=unit,
            unit_scale=unit_scale,
            leave=False,
            dynamic_ncols=True,
        )
        try:
            yield bar
        finally:
            bar.close()
