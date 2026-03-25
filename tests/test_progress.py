"""Unit tests for ScanProgressDisplay state management."""

from __future__ import annotations

from agentgate.progress import ItemStatus, ScanProgressDisplay


class TestScanProgressDisplay:
    def test_initial_state_all_pending(self):
        p = ScanProgressDisplay(["a", "b", "c"])
        for item in p._items.values():
            assert item.status == ItemStatus.PENDING

    def test_mark_running(self):
        p = ScanProgressDisplay(["detector_1"])
        p.mark_running("detector_1", total_tests=10)
        item = p._items["detector_1"]
        assert item.status == ItemStatus.RUNNING
        assert item.tests_total == 10

    def test_update_tests(self):
        p = ScanProgressDisplay(["d"])
        p.mark_running("d", total_tests=5)
        p.update_tests("d", done=3, failed=1)
        item = p._items["d"]
        assert item.tests_done == 3
        assert item.failures == 1

    def test_mark_completed(self):
        p = ScanProgressDisplay(["d"])
        p.mark_running("d")
        p.mark_completed("d", total=10, failed=2)
        item = p._items["d"]
        assert item.status == ItemStatus.COMPLETED
        assert item.tests_done == 10
        assert item.tests_total == 10
        assert item.failures == 2

    def test_mark_error(self):
        p = ScanProgressDisplay(["d"])
        p.mark_running("d")
        p.mark_error("d", "connection refused")
        item = p._items["d"]
        assert item.status == ItemStatus.ERROR
        assert item.error == "connection refused"

    def test_unknown_name_is_noop(self):
        p = ScanProgressDisplay(["a"])
        p.mark_running("nonexistent")
        p.update_tests("nonexistent", done=1)
        p.mark_completed("nonexistent")
        p.mark_error("nonexistent", "oops")
        assert p._items["a"].status == ItemStatus.PENDING

    def test_order_preserved(self):
        names = ["z", "a", "m"]
        p = ScanProgressDisplay(names)
        assert p._order == names

    def test_rich_renderable_scan_mode(self):
        from rich.console import Console

        p = ScanProgressDisplay(["x", "y"], mode="scan")
        p.mark_running("x", total_tests=5)
        p.update_tests("x", done=3)
        p.mark_completed("y", total=2, failed=1)
        c = Console(file=None, force_terminal=True, width=120)
        # Should not raise
        with c.capture() as capture:
            c.print(p)
        output = capture.get()
        assert "x" in output
        assert "y" in output

    def test_rich_renderable_trust_mode(self):
        from rich.console import Console

        p = ScanProgressDisplay(["check_a", "check_b"], mode="trust")
        p.mark_running("check_a")
        p.mark_completed("check_b")
        c = Console(file=None, force_terminal=True, width=120)
        with c.capture() as capture:
            c.print(p)
        output = capture.get()
        assert "check_a" in output
        assert "check_b" in output

    def test_completed_without_explicit_total(self):
        p = ScanProgressDisplay(["d"])
        p.mark_completed("d")
        item = p._items["d"]
        assert item.status == ItemStatus.COMPLETED
        assert item.tests_done == 0
        assert item.tests_total == 0
