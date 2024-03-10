import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import *
import threading

from scapy.layers.inet import ICMP, TCP, IP, UDP
from scapy.layers.l2 import arping


def proto2str(protocol):
    protocols = {1: 'icmp', 6: 'tcp', 17: 'udp'}
    return protocols.get(protocol, 'unknown')


class HostDiscoveryTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Host Discovery Tool")
        self.geometry("500x400")

        # Create tabs
        self.tab_control = ttk.Notebook(self)
        self.arp_tab = ttk.Frame(self.tab_control)
        self.icmp_tab = ttk.Frame(self.tab_control)
        self.udp_tab = ttk.Frame(self.tab_control)
        self.tcp_tab = ttk.Frame(self.tab_control)
        self.ip_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.arp_tab, text="ARP Ping Scan")
        self.tab_control.add(self.icmp_tab, text="ICMP Ping Scan")
        self.tab_control.add(self.udp_tab, text="UDP Ping Scan")
        self.tab_control.add(self.tcp_tab, text="TCP Ping Scan")
        self.tab_control.add(self.ip_tab, text="IP Protocol Ping Scan")
        self.tab_control.pack(expand=1, fill="both")

        # ARP Ping Scan tab
        self.arp_ip_range_label = ttk.Label(self.arp_tab, text="IP Range:")
        self.arp_ip_range_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.arp_ip_range_entry = ttk.Entry(self.arp_tab)
        self.arp_ip_range_entry.grid(row=0, column=1, padx=10, pady=10)
        self.arp_scan_button = ttk.Button(self.arp_tab, text="Scan", command=self.arp_ping_scan)
        self.arp_scan_button.grid(row=0, column=2, padx=10, pady=10)
        self.arp_results_text = scrolledtext.ScrolledText(self.arp_tab, width=60, height=20)
        self.arp_results_text.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

        # ICMP Ping Scan tab
        self.icmp_ip_range_label = ttk.Label(self.icmp_tab, text="IP Range:")
        self.icmp_ip_range_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.icmp_ip_range_entry = ttk.Entry(self.icmp_tab)
        self.icmp_ip_range_entry.grid(row=0, column=1, padx=10, pady=10)
        self.icmp_ping_type_label = ttk.Label(self.icmp_tab, text="Ping Type:")
        self.icmp_ping_type_label.grid(row=0, column=2, padx=10, pady=10, sticky="w")
        self.icmp_ping_type_var = tk.StringVar()
        self.icmp_ping_type_combo = ttk.Combobox(self.icmp_tab, textvariable=self.icmp_ping_type_var,
                                                 values=["Echo Ping", "Echo Ping Sweep", "Timestamp Ping",
                                                         "Address Mask Ping"])
        self.icmp_ping_type_combo.grid(row=0, column=3, padx=10, pady=10)
        self.icmp_scan_button = ttk.Button(self.icmp_tab, text="Scan", command=self.icmp_ping_scan)
        self.icmp_scan_button.grid(row=0, column=4, padx=10, pady=10)
        self.icmp_results_text = scrolledtext.ScrolledText(self.icmp_tab, width=60, height=20)
        self.icmp_results_text.grid(row=1, column=0, columnspan=5, padx=10, pady=10)

        # UDP Ping Scan tab
        self.udp_ip_range_label = ttk.Label(self.udp_tab, text="IP Range:")
        self.udp_ip_range_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.udp_ip_range_entry = ttk.Entry(self.udp_tab)
        self.udp_ip_range_entry.grid(row=0, column=1, padx=10, pady=10)
        self.udp_port_label = ttk.Label(self.udp_tab, text="Port:")
        self.udp_port_label.grid(row=0, column=2, padx=10, pady=10, sticky="w")
        self.udp_port_entry = ttk.Entry(self.udp_tab)
        self.udp_port_entry.grid(row=0, column=3, padx=10, pady=10)
        self.udp_scan_button = ttk.Button(self.udp_tab, text="Scan", command=self.udp_ping_scan)
        self.udp_scan_button.grid(row=0, column=4, padx=10, pady=10)
        self.udp_results_text = scrolledtext.ScrolledText(self.udp_tab, width=60, height=20)
        self.udp_results_text.grid(row=1, column=0, columnspan=5, padx=10, pady=10)

        # TCP Ping Scan tab
        self.tcp_ip_range_label = ttk.Label(self.tcp_tab, text="IP Range:")
        self.tcp_ip_range_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.tcp_ip_range_entry = ttk.Entry(self.tcp_tab)
        self.tcp_ip_range_entry.grid(row=0, column=1, padx=10, pady=10)
        self.tcp_scan_type_label = ttk.Label(self.tcp_tab, text="Scan Type:")
        self.tcp_scan_type_label.grid(row=0, column=2, padx=10, pady=10, sticky="w")
        self.tcp_scan_type_var = tk.StringVar()
        self.tcp_scan_type_combo = ttk.Combobox(self.tcp_tab, textvariable=self.tcp_scan_type_var,
                                                values=["SYN Scan", "ACK Scan", "Null Scan", "XMAS Scan", "FIN Scan"])
        self.tcp_scan_type_combo.grid(row=0, column=3, padx=10, pady=10)
        self.tcp_scan_button = ttk.Button(self.tcp_tab, text="Scan", command=self.tcp_ping_scan)
        self.tcp_scan_button.grid(row=0, column=4, padx=10, pady=10)
        self.tcp_results_text = scrolledtext.ScrolledText(self.tcp_tab, width=60, height=20)
        self.tcp_results_text.grid(row=1, column=0, columnspan=5, padx=10, pady=10)

        # IP Protocol Ping Scan tab
        self.ip_ip_range_label = ttk.Label(self.ip_tab, text="IP Range:")
        self.ip_ip_range_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.ip_ip_range_entry = ttk.Entry(self.ip_tab)
        self.ip_ip_range_entry.grid(row=0, column=1, padx=10, pady=10)
        self.ip_protocols_label = ttk.Label(self.ip_tab, text="Protocols:")
        self.ip_protocols_label.grid(row=0, column=2, padx=10, pady=10, sticky="w")
        self.ip_protocols_var = tk.StringVar()
        self.ip_protocols_entry = ttk.Entry(self.ip_tab, textvariable=self.ip_protocols_var)
        self.ip_protocols_entry.grid(row=0, column=3, padx=10, pady=10)
        self.ip_scan_button = ttk.Button(self.ip_tab, text="Scan", command=self.ip_protocol_ping_scan)
        self.ip_scan_button.grid(row=0, column=4, padx=10, pady=10)
        self.ip_results_text = scrolledtext.ScrolledText(self.ip_tab, width=60, height=20)
        self.ip_results_text.grid(row=1, column=0, columnspan=5, padx=10, pady=10)

        # Run the main loop
        self.mainloop()

    def arp_ping_scan(self):
        ip_range = self.arp_ip_range_entry.get()
        self.arp_results_text.delete("1.0", tk.END)
        self.arp_results_text.insert(tk.END, "Scanning...\n")

        def scan_thread():
            answered, unanswered = arping(ip_range, verbose=0)
            self.arp_results_text.insert(tk.END, "ARP Ping Scan Results:\n")
            self.arp_results_text.insert(tk.END, "Alive Hosts:\n")
            for res in answered:
                self.arp_results_text.insert(tk.END, f"{res[0].pdst} ({res[0].hwdst})\n")

        thread = threading.Thread(target=scan_thread)
        thread.start()

    def icmp_ping_scan(self):
        ip_range = self.icmp_ip_range_entry.get()
        ping_type = ["Echo Ping", "Echo Ping Sweep", "Timestamp Ping", "Address Mask Ping"].index(
            self.icmp_ping_type_var.get()) + 1
        self.icmp_results_text.delete("1.0", tk.END)
        self.icmp_results_text.insert(tk.END, "Scanning...\n")

        def scan_thread():
            if ping_type == 1:
                ping = IP(dst=ip_range) / ICMP()
            elif ping_type == 2:
                ping = IP(dst=[f"{ip_range}/{32}" for ip in ip_range.split('-')]) / ICMP()
            elif ping_type == 3:
                ping = IP(dst=ip_range) / ICMP(type=13)
            elif ping_type == 4:
                ping = IP(dst=ip_range) / ICMP(type=17)

            answered, unanswered = sr(ping, timeout=2, verbose=0)
            self.icmp_results_text.insert(tk.END,
                                          f"ICMP {['Echo Ping', 'Echo Ping Sweep', 'Timestamp Ping', 'Address Mask Ping'][ping_type - 1]} Results:\n")
            self.icmp_results_text.insert(tk.END, "Alive Hosts:\n")
            for req, res in answered:
                self.icmp_results_text.insert(tk.END, f"{res.sprintf('%IP.src%')}\n")

        thread = threading.Thread(target=scan_thread)
        thread.start()

    def udp_ping_scan(self):
        ip_range = self.udp_ip_range_entry.get()
        port = int(self.udp_port_entry.get())
        self.udp_results_text.delete("1.0", tk.END)
        self.udp_results_text.insert(tk.END, "Scanning...\n")

        def scan_thread():
            ping = IP(dst=ip_range) / UDP(dport=port)
            answered, unanswered = sr(ping, timeout=2, verbose=0)
            self.udp_results_text.insert(tk.END, f"UDP Ping Scan (Port {port}) Results:\n")
            self.udp_results_text.insert(tk.END, "Alive Hosts:\n")
            for req, res in answered:
                self.udp_results_text.insert(tk.END, f"{res.sprintf('%IP.src%')}\n")

        thread = threading.Thread(target=scan_thread)
        thread.start()

    def tcp_ping_scan(self):
        ip_range = self.tcp_ip_range_entry.get()
        scan_type = ["SYN Scan", "ACK Scan", "Null Scan", "XMAS Scan", "FIN Scan"].index(
            self.tcp_scan_type_var.get()) + 1
        self.tcp_results_text.delete("1.0", tk.END)
        self.tcp_results_text.insert(tk.END, "Scanning...\n")

        def scan_thread():
            if scan_type == 1:
                ping = IP(dst=ip_range) / TCP(flags="S")
            elif scan_type == 2:
                ping = IP(dst=ip_range) / TCP(flags="A")
            elif scan_type == 3:
                ping = IP(dst=ip_range) / TCP(flags=0)
            elif scan_type == 4:
                ping = IP(dst=ip_range) / TCP(flags="FPU")  # XMAS Scan (Does not work on Windows)
            elif scan_type == 5:
                ping = IP(dst=ip_range) / TCP(flags="F")

            answered, unanswered = sr(ping, timeout=2, verbose=0)
            self.tcp_results_text.insert(tk.END,
                                         f"TCP {['SYN', 'ACK', 'Null', 'XMAS', 'FIN'][scan_type - 1]} Scan Results:\n")
            self.tcp_results_text.insert(tk.END, "Alive Hosts:\n")
            for req, res in answered:
                self.tcp_results_text.insert(tk.END, f"{res.sprintf('%IP.src%')}\n")

        thread = threading.Thread(target=scan_thread)
        thread.start()

    def ip_protocol_ping_scan(self):
        ip_range = self.ip_ip_range_entry.get()
        protocols = [int(p) for p in self.ip_protocols_var.get().split()]
        self.ip_results_text.delete("1.0", tk.END)
        self.ip_results_text.insert(tk.END, "Scanning...\n")

        def scan_thread():
            for protocol in protocols:
                ping = IP(dst=ip_range, proto=protocol)
                answered, unanswered = sr(ping, timeout=2, verbose=0)
                self.ip_results_text.insert(tk.END, f"IP Protocol {proto2str(protocol)} Ping Scan Results:\n")
                self.ip_results_text.insert(tk.END, "Alive Hosts:\n")
                for req, res in answered:
                    self.ip_results_text.insert(tk.END, f"{res.sprintf('%IP.src%')}\n")

        thread = threading.Thread(target=scan_thread)
        thread.start()


if __name__ == "__main__":
    app = HostDiscoveryTool()
