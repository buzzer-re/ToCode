"""Change notifications from the database, so `sync` sees what scripts changed.

Edits made through the edit tools already record what they make stale; edits
made by `eval` scripts are only partly visible to sync's diff (it sees names
and prototypes, not comments or a function body's details). These hooks mark
the affected functions while the session runs. Installing them is best
effort: a backend without notifications relies on the diff and `touch()`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .worker import LiveSession


def install(live: "LiveSession") -> Any:
    try:
        if live.backend == "ida":
            return _ida(live)
        if live.backend == "binja":
            return _binja(live)
    except Exception as exc:  # noqa: BLE001 - notifications are optional
        live.log(f"live: change hooks unavailable: {exc}")
    return None


def _ida(live: "LiveSession") -> Any:
    import ida_funcs  # type: ignore[import-not-found]
    import ida_idp  # type: ignore[import-not-found]

    def mark(address: Any) -> None:
        func = ida_funcs.get_func(int(address))
        if func is not None:
            live.dirty.add(int(func.start_ea))

    class Hooks(ida_idp.IDB_Hooks):  # type: ignore[misc]
        # Signatures differ between IDA versions: take what comes.
        def renamed(self, ea: int, *_args: Any) -> int:
            mark(ea)
            return 0

        def cmt_changed(self, ea: int, *_args: Any) -> int:
            mark(ea)
            return 0

        def extra_cmt_changed(self, ea: int, *_args: Any) -> int:
            mark(ea)
            return 0

        def range_cmt_changed(self, _kind: Any, area: Any, *_args: Any) -> int:
            start = getattr(area, "start_ea", None)
            if start is not None:
                mark(start)
            return 0

        def ti_changed(self, ea: int, *_args: Any) -> int:
            mark(ea)
            return 0

        def func_added(self, pfn: Any) -> int:
            live.dirty.add(int(pfn.start_ea))
            live.functions_changed = True
            return 0

        def deleting_func(self, _pfn: Any) -> int:
            live.functions_changed = True
            return 0

        def local_types_changed(self, *_args: Any) -> int:
            live.types_changed = True
            return 0

    hooks = Hooks()
    hooks.hook()
    return hooks


def _binja(live: "LiveSession") -> Any:
    bn = live.session._bn
    bv = live.session._bv
    base = getattr(bn, "BinaryDataNotification", None)
    if base is None or not hasattr(bv, "register_notification"):
        return None

    class Notifications(base):  # type: ignore[misc, valid-type]
        def function_added(self, _view: Any, func: Any) -> None:
            live.dirty.add(int(func.start))
            live.functions_changed = True

        def function_removed(self, _view: Any, _func: Any) -> None:
            live.functions_changed = True

        def function_updated(self, _view: Any, func: Any) -> None:
            live.dirty.add(int(func.start))

        def type_defined(self, *_args: Any) -> None:
            live.types_changed = True

        def type_undefined(self, *_args: Any) -> None:
            live.types_changed = True

    notifications = Notifications()
    bv.register_notification(notifications)
    return notifications
