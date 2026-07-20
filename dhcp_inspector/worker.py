"""QThread worker: fast DNS/ping sweep first, then WMI only where it can work."""
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt5.QtCore import QThread, pyqtSignal

from . import checks, config


class ScanWorker(QThread):
    row_ready = pyqtSignal(int, dict)
    progress = pyqtSignal(int, int, str)  # done, total, phase label
    finished_all = pyqtSignal()

    def __init__(self, targets: list[tuple[int, str]], ad_info: dict | None = None):
        """targets: (table row, computer name) pairs — any subset of the table."""
        super().__init__()
        self._targets = targets
        # name -> AD record ({domain, ad_os, enabled, password_last_set,
        # last_logon}); merged into each result so the domain check has AD
        # facts even when the machine can't be reached over WMI.
        self._ad_info = ad_info or {}
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def _with_ad(self, computer: str, result: dict) -> dict:
        ad = self._ad_info.get(computer, {})
        result["ad_domain"] = ad.get("domain")
        result["ad_os"] = ad.get("ad_os")
        result["ad_enabled"] = ad.get("enabled")
        result["ad_password_last_set"] = ad.get("password_last_set")
        result["ad_last_logon"] = ad.get("last_logon")
        return result

    def _probe_one(self, computer: str) -> dict:
        try:
            probe = checks.resolve_and_ping(computer)
        except Exception as exc:
            probe = {"ip": None, "dns_ok": False, "ping": False, "error": str(exc)}
        probe["computer_name"] = computer
        probe["wmi_ok"] = False
        return self._with_ad(computer, probe)

    def _wmi_one(self, computer: str) -> dict:
        try:
            return checks.check_computer(computer)
        except Exception as exc:
            return {"computer_name": computer, "wmi_ok": False, "error": str(exc)}

    def run(self):
        settings = config.get_settings()
        try:
            # Phase 1: DNS + ping every target with high parallelism. Cheap,
            # so dead machines cost ~2s here instead of a long WMI timeout.
            survivors: list[tuple[int, dict]] = []
            done = 0
            with ThreadPoolExecutor(max_workers=settings.max_parallel_ping) as pool:
                futures = {
                    pool.submit(self._probe_one, name): row
                    for row, name in self._targets
                }
                for future in as_completed(futures):
                    if self._stop_requested:
                        for pending in futures:
                            pending.cancel()
                        return
                    row = futures[future]
                    probe = future.result()
                    self.row_ready.emit(row, probe)
                    if probe.get("ping") or (
                        not settings.wmi_only_ping_ok and probe.get("dns_ok")
                    ):
                        survivors.append((row, probe))
                    done += 1
                    self.progress.emit(done, len(self._targets), "Ping sweep")

            # Phase 2: WMI over DCOM, only for machines phase 1 deemed alive.
            done = 0
            with ThreadPoolExecutor(max_workers=settings.max_parallel_wmi) as pool:
                futures2 = {
                    pool.submit(self._wmi_one, probe["computer_name"]): (row, probe)
                    for row, probe in survivors
                }
                for future in as_completed(futures2):
                    if self._stop_requested:
                        for pending in futures2:
                            pending.cancel()
                        return
                    row, probe = futures2[future]
                    # WMI fields overlay the phase-1 probe (ip/dns/ping kept).
                    merged = {**probe, **future.result()}
                    self.row_ready.emit(row, merged)
                    done += 1
                    self.progress.emit(done, len(survivors), "WMI check")
        finally:
            # Always emitted, even if a check blows up — otherwise the GUI
            # buttons stay disabled forever.
            self.finished_all.emit()
