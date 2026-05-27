from __future__ import annotations

from contextlib import contextmanager
import sys
from typing import Iterator

try:  # pragma: no cover - dependency presence is covered by CLI/export tests.
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    tqdm = None


class _NullProgress:
    def update(self, _value: int = 1) -> None:
        return

    def close(self) -> None:
        return


class Progress:
    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled

    def log(self, message: str) -> None:
        if self.enabled:
            print(message, file=sys.stderr)

    @contextmanager
    def bar(self, *, total: int, desc: str, unit: str) -> Iterator[object]:
        if not self.enabled or tqdm is None:
            yield _NullProgress()
            return
        bar = tqdm(total=total, desc=desc, unit=unit, leave=False, dynamic_ncols=True)
        try:
            yield bar
        finally:
            bar.close()
