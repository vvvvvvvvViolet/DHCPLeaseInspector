"""Simple Tkinter GUI for DHCP Lease Inspector."""
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext

from . import client_status, dhcp_lease, dhcp_scan, system_info


class DHCPInspectorApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("DHCP Lease Inspector")
        self.root.geometry("720x520")

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        self.system_tab = self._make_tab(notebook, "Domain / OS", self.run_system_info)
        self.lease_tab = self._make_tab(notebook, "DHCP Lease", self.run_dhcp_lease)
        self.scan_tab = self._make_tab(notebook, "Scan DHCP Servers", self.run_dhcp_scan)
        self.service_tab = self._make_tab(notebook, "DHCP Client Service", self.run_client_status)

    def _make_tab(self, notebook: ttk.Notebook, title: str, action):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=title)

        button = ttk.Button(frame, text=f"Run: {title}", command=action)
        button.pack(anchor="w", padx=8, pady=8)

        text = scrolledtext.ScrolledText(frame, wrap="word", font=("Consolas", 10))
        text.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        text.configure(state="disabled")

        frame.button = button
        frame.text = text
        return frame

    def _set_text(self, frame: ttk.Frame, content: str):
        frame.text.configure(state="normal")
        frame.text.delete("1.0", "end")
        frame.text.insert("1.0", content)
        frame.text.configure(state="disabled")

    def _run_async(self, frame: ttk.Frame, worker, on_success):
        frame.button.configure(state="disabled")
        self._set_text(frame, "Running...\n")

        def task():
            try:
                result = worker()
                self.root.after(0, lambda: (on_success(result), frame.button.configure(state="normal")))
            except Exception as exc:
                self.root.after(0, lambda: (self._set_text(frame, f"Error: {exc}"), frame.button.configure(state="normal")))

        threading.Thread(target=task, daemon=True).start()

    def run_system_info(self):
        def on_success(info: dict):
            lines = [
                f"Computer name     : {info['computer_name']}",
                f"Joined to domain  : {'Yes' if info['joined_to_domain'] else 'No'}",
                f"Domain/Workgroup  : {info['domain_or_workgroup']}",
                "",
                f"OS name           : {info['os_name']}",
                f"OS version        : {info['os_version']} (build {info['os_build']})",
                f"OS architecture   : {info['os_architecture']}",
            ]
            self._set_text(self.system_tab, "\n".join(lines))

        self._run_async(self.system_tab, system_info.get_system_info, on_success)

    def run_dhcp_lease(self):
        def on_success(leases: list):
            if not leases:
                self._set_text(self.lease_tab, "No adapters with an active DHCP lease were found.")
                return
            blocks = []
            for lease in leases:
                blocks.append(
                    "\n".join([
                        f"Adapter        : {lease.get('adapter')}",
                        f"IPv4 address   : {lease.get('ipv4_address', '-')}",
                        f"Subnet mask    : {lease.get('subnet_mask', '-')}",
                        f"DHCP server    : {lease.get('dhcp_server', '-')}",
                        f"Lease obtained : {lease.get('lease_obtained', '-')}",
                        f"Lease expires  : {lease.get('lease_expires', '-')}",
                    ])
                )
            self._set_text(self.lease_tab, "\n\n".join(blocks))

        self._run_async(self.lease_tab, dhcp_lease.get_dhcp_leases, on_success)

    def run_dhcp_scan(self):
        def on_success(offers: list):
            if not offers:
                self._set_text(self.scan_tab, "No DHCP servers responded within the timeout.")
                return
            lines = [f"{o['server_ip']}  ->  offered {o['offered_ip']}" for o in offers]
            unique_servers = sorted({o["server_ip"] for o in offers})
            header = f"Found {len(unique_servers)} DHCP server(s):\n"
            self._set_text(self.scan_tab, header + "\n".join(lines))

        self._run_async(self.scan_tab, dhcp_scan.scan_for_dhcp_servers, on_success)

    def run_client_status(self):
        def on_success(status: dict):
            lines = [
                f"Service state : {status['status']}",
                f"Start type    : {status['start_type']}",
            ]
            self._set_text(self.service_tab, "\n".join(lines))

        self._run_async(self.service_tab, client_status.get_dhcp_client_status, on_success)


def main():
    root = tk.Tk()
    DHCPInspectorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
