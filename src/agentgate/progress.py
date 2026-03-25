"""Real-time progress display for scans using Rich Live rendering."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum

from rich.console import Console, ConsoleOptions, RenderResult
from rich.table import Table
from rich.text import Text


class ItemStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class _ItemState:
    name: str
    status: ItemStatus = ItemStatus.PENDING
    tests_done: int = 0
    tests_total: int = 0
    failures: int = 0
    error: str = ""


class ScanProgressDisplay:
    """Thread-safe progress display that renders as a Rich renderable.

    Rich ``Live`` refreshes from a daemon thread while asyncio updates
    state on the main thread.  A lock protects shared state.
    """

    def __init__(self, names: list[str], *, mode: str = "scan") -> None:
        self._lock = threading.Lock()
        self._mode = mode  # "scan" or "trust"
        self._items: dict[str, _ItemState] = {
            name: _ItemState(name=name) for name in names
        }
        self._order = list(names)

    # -- public API (called from asyncio on main thread) --

    def mark_running(self, name: str, total_tests: int = 0) -> None:
        with self._lock:
            item = self._items.get(name)
            if item is None:
                return
            item.status = ItemStatus.RUNNING
            if total_tests:
                item.tests_total = total_tests

    def update_tests(self, name: str, done: int, total: int = 0, failed: int = 0) -> None:
        with self._lock:
            item = self._items.get(name)
            if item is None:
                return
            item.tests_done = done
            if total:
                item.tests_total = total
            item.failures = failed

    def mark_completed(self, name: str, total: int = 0, failed: int = 0) -> None:
        with self._lock:
            item = self._items.get(name)
            if item is None:
                return
            item.status = ItemStatus.COMPLETED
            if total:
                item.tests_total = total
                item.tests_done = total
            item.failures = failed

    def mark_error(self, name: str, error: str) -> None:
        with self._lock:
            item = self._items.get(name)
            if item is None:
                return
            item.status = ItemStatus.ERROR
            item.error = error

    # -- Rich renderable protocol --

    def __rich_console__(
        self, console: Console, options: ConsoleOptions
    ) -> RenderResult:
        with self._lock:
            if self._mode == "trust":
                yield from self._render_trust()
            else:
                yield from self._render_scan()

    def _render_scan(self) -> RenderResult:
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("name", min_width=24)
        table.add_column("bar", min_width=12)
        table.add_column("count", min_width=8, justify="right")
        table.add_column("status", min_width=10)
        table.add_column("extra")

        for name in self._order:
            item = self._items[name]
            label = Text(f"  {item.name}", style="bold")
            bar_text, count_text = self._progress_bar(item)
            status_text = self._status_text(item)
            extra = self._extra_text(item)
            table.add_row(label, bar_text, count_text, status_text, extra)

        yield table

    def _render_trust(self) -> RenderResult:
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("icon", width=3)
        table.add_column("name")
        table.add_column("status", justify="right")

        status_icons = {
            ItemStatus.PENDING: Text("○", style="dim"),
            ItemStatus.RUNNING: Text("◐", style="yellow"),
            ItemStatus.COMPLETED: Text("✓", style="green"),
            ItemStatus.ERROR: Text("✗", style="red"),
        }
        status_labels = {
            ItemStatus.PENDING: Text("pending", style="dim"),
            ItemStatus.RUNNING: Text("running", style="yellow"),
            ItemStatus.COMPLETED: Text("done", style="green"),
            ItemStatus.ERROR: Text("error", style="red"),
        }

        for name in self._order:
            item = self._items[name]
            icon = status_icons[item.status]
            label = Text(f"  {item.name}")
            status = status_labels[item.status]
            table.add_row(icon, label, status)

        yield table

    def _progress_bar(self, item: _ItemState) -> tuple[Text, Text]:
        if item.status == ItemStatus.PENDING:
            return Text("", style="dim"), Text("—", style="dim")
        if item.tests_total == 0:
            if item.status == ItemStatus.RUNNING:
                return Text("", style="dim"), Text("...", style="yellow")
            return Text("", style="dim"), Text("", style="dim")

        filled = int(10 * item.tests_done / item.tests_total) if item.tests_total else 0
        empty = 10 - filled
        bar = Text("█" * filled, style="green") + Text("░" * empty, style="dim")
        count = Text(f"{item.tests_done}/{item.tests_total}")
        return bar, count

    def _status_text(self, item: _ItemState) -> Text:
        if item.status == ItemStatus.PENDING:
            return Text("pending", style="dim")
        if item.status == ItemStatus.RUNNING:
            return Text("running", style="yellow")
        if item.status == ItemStatus.COMPLETED:
            return Text("done", style="green")
        return Text("error", style="red")

    def _extra_text(self, item: _ItemState) -> Text:
        if item.failures > 0:
            return Text(f"{item.failures} failed", style="red")
        if item.status == ItemStatus.ERROR and item.error:
            return Text(item.error[:40], style="red dim")
        return Text("")
