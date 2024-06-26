import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import *
import threading

from scapy.layers.inet import ICMP, TCP, IP, UDP
from scapy.layers.l2 import arping, Ether, ARP


def proto2str(protocol):
    """
    Convert protocol number to protocol name
    :param protocol:
    :return:
    """
    protocols = {1: 'icmp', 6: 'tcp', 17: 'udp'}
    return protocols.get(protocol, 'unknown')


class HostDiscoveryTool(tk.Tk):
    def __init__(self):
        """
        Initialize the Host Discovery Tool
        """
        super().__init__()
        self.title("Host Discovery Tool")
        self.geometry("600x400")
        self.iconbitmap("icon.ico")

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

        # Configure grid weights for each tab
        self.arp_tab.rowconfigure(1, weight=1)
        self.arp_tab.columnconfigure(0, weight=1)
        self.arp_tab.columnconfigure(1, weight=1)
        self.arp_tab.columnconfigure(2, weight=1)

        self.icmp_tab.rowconfigure(1, weight=1)
        self.icmp_tab.columnconfigure(0, weight=1)
        self.icmp_tab.columnconfigure(1, weight=1)
        self.icmp_tab.columnconfigure(2, weight=1)
        self.icmp_tab.columnconfigure(3, weight=1)
        self.icmp_tab.columnconfigure(4, weight=1)

        self.udp_tab.rowconfigure(1, weight=1)
        self.udp_tab.columnconfigure(0, weight=1)
        self.udp_tab.columnconfigure(1, weight=1)
        self.udp_tab.columnconfigure(2, weight=1)
        self.udp_tab.columnconfigure(3, weight=1)
        self.udp_tab.columnconfigure(4, weight=1)

        self.tcp_tab.rowconfigure(1, weight=1)
        self.tcp_tab.columnconfigure(0, weight=1)
        self.tcp_tab.columnconfigure(1, weight=1)
        self.tcp_tab.columnconfigure(2, weight=1)
        self.tcp_tab.columnconfigure(3, weight=1)
        self.tcp_tab.columnconfigure(4, weight=1)

        self.ip_tab.rowconfigure(1, weight=1)
        self.ip_tab.columnconfigure(0, weight=1)
        self.ip_tab.columnconfigure(1, weight=1)
        self.ip_tab.columnconfigure(2, weight=1)
        self.ip_tab.columnconfigure(3, weight=1)
        self.ip_tab.columnconfigure(4, weight=1)

        # ARP Ping Scan tab
        self.arp_ip_range_label = ttk.Label(self.arp_tab, text="IP Range:")
        self.arp_ip_range_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.arp_ip_range_entry = ttk.Entry(self.arp_tab)
        self.arp_ip_range_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.arp_scan_button = ttk.Button(self.arp_tab, text="Scan", command=self.arp_ping_scan)
        self.arp_scan_button.grid(row=0, column=2, padx=10, pady=10, sticky="ew")
        self.arp_results_text = scrolledtext.ScrolledText(self.arp_tab, width=60, height=20)
        self.arp_results_text.grid(row=1, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

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
        self.icmp_results_text.grid(row=1, column=0, columnspan=5, padx=10, pady=10, sticky="nsew")

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
        self.udp_results_text.grid(row=1, column=0, columnspan=5, padx=10, pady=10, sticky="nsew")

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
        self.tcp_results_text.grid(row=1, column=0, columnspan=5, padx=10, pady=10, sticky="nsew")

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
        self.ip_results_text.grid(row=1, column=0, columnspan=5, padx=10, pady=10, sticky="nsew")

        # Run the main loop
        self.mainloop()

    def arp_ping_scan(self):
        """
        This function performs an ARP Ping Scan. It retrieves the IP range from the GUI,
        then starts a new thread to perform the scan.

        :return: None
        """
        # Get the IP range from the GUI
        ip_range = self.arp_ip_range_entry.get()
        # Clear the results text box in the GUI
        self.arp_results_text.delete("1.0", tk.END)
        # Insert initial scanning message to the results text box in the GUI
        self.arp_results_text.insert(tk.END, "Scanning...\n")

        def scan_thread():
            """
            This function performs the ARP Ping Scan in a separate thread. It sends ARP packets to the specified IP range
            and updates the results text box in the GUI with the results.

            :return: None
            """
            # Send the ARP packet and collect the responses
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=2, verbose=0)
            # Update the results text box in the GUI with the results
            self.arp_results_text.insert(tk.END, "ARP Ping Scan Results:\n")
            self.arp_results_text.insert(tk.END, "Alive Hosts:\n")
            # If responses were received, update the results text box in the GUI with the IP addresses and MAC addresses of the hosts
            for snd, rcv in ans:
                response_time = rcv.time - snd.sent_time
                ip_addr = rcv[ARP].psrc
                mac_addr = rcv[Ether].src
                self.arp_results_text.insert(tk.END,
                                             f"IP: {ip_addr} - MAC: {mac_addr} - Response Time: {response_time:.3f}s\n")

        # Start the scan thread
        thread = threading.Thread(target=scan_thread)
        thread.start()

    def icmp_ping_scan(self):
        """
        This function performs an ICMP Ping Scan. It retrieves the IP range and ping type from the GUI,
        then starts a new thread to perform the scan.

        :return: None
        """
        # Get the IP range from the GUI
        ip_range = self.icmp_ip_range_entry.get()
        # Get the ping type from the GUI and convert it to an integer
        ping_type = ["Echo Ping", "Echo Ping Sweep", "Timestamp Ping", "Address Mask Ping"].index(
            self.icmp_ping_type_var.get()) + 1
        # Clear the results text box in the GUI
        self.icmp_results_text.delete("1.0", tk.END)

        def scan_thread():
            """
            This function performs the ICMP Ping Scan in a separate thread. It sends ICMP packets based on the ping type
            and updates the results text box in the GUI with the results.

            :return: None
            """
            # Create the ICMP packet to send based on the ping type
            if ping_type == 1:
                ping = IP(dst=ip_range) / ICMP()
            elif ping_type == 2:
                ping = IP(dst=[f"{ip_range}/{32}" for ip in ip_range.split('-')]) / ICMP()
            elif ping_type == 3:
                ping = IP(dst=ip_range) / ICMP(type=13)
            elif ping_type == 4:
                ping = IP(dst=ip_range) / ICMP(type=17)

            # Send the ICMP packet and collect the responses
            answered, unanswered = sr(ping, timeout=2, verbose=0)
            # Update the results text box in the GUI with the results
            self.icmp_results_text.insert(tk.END, f"\nFinished sending {len(unanswered) + len(answered)} packets.\n")
            if len(answered) > 0:
                self.icmp_results_text.insert(tk.END, ".\\" * len(answered) + "\n")
            self.icmp_results_text.insert(tk.END,
                                          f"Received {len(answered) + len(unanswered)} packets, got {len(answered)} answers, remaining {len(unanswered)} packets\n")
            self.icmp_results_text.insert(tk.END, "Alive Hosts:\n")
            # If responses were received, update the results text box in the GUI with the IP addresses of the hosts
            for req, res in answered:
                response_time = res.time - req.sent_time
                ip_addr = res.sprintf('%IP.src%')
                icmp_type = res[ICMP].type
                icmp_code = res[ICMP].code
                self.icmp_results_text.insert(tk.END, f"{ip_addr}\n")

        # Start the scan thread
        thread = threading.Thread(target=scan_thread)
        thread.start()

    def udp_ping_scan(self):
        """
        This function performs a UDP Ping Scan. It retrieves the IP range and port from the GUI,
        then starts a new thread to perform the scan.

        :return: None
        """
        # Get the IP range from the GUI
        ip_range = self.udp_ip_range_entry.get()
        # Get the port from the GUI and convert it to an integer
        port = int(self.udp_port_entry.get())
        # Clear the results text box in the GUI
        self.udp_results_text.delete("1.0", tk.END)

        def scan_thread():
            """
            This function performs the UDP Ping Scan in a separate thread. It sends UDP packets to the specified port
            and updates the results text box in the GUI with the results.

            :return: None
            """
            # Create the UDP packet to send
            ping = IP(dst=ip_range) / UDP(dport=port)
            # Send the UDP packet and collect the responses
            answered, unanswered = sr(ping, timeout=2, verbose=0)
            # Update the results text box in the GUI with the results
            self.udp_results_text.insert(tk.END, f"\nFinished sending {len(unanswered) + len(answered)} packets.\n")
            if len(answered) > 0:
                self.udp_results_text.insert(tk.END, ".\\" * len(answered) + "\n")
            self.udp_results_text.insert(tk.END,
                                         f"Received {len(answered) + len(unanswered)} packets, got {len(answered)} answers, remaining {len(unanswered)} packets\n")

            # If no responses were received, update the results text box in the GUI
            if len(answered) == 0:
                self.udp_results_text.insert(tk.END, "No responses received for UDP Ping Scan.\n")
            else:
                # If responses were received, update the results text box in the GUI with the IP addresses of the hosts
                self.udp_results_text.insert(tk.END, "Alive Hosts:\n")
                for req, res in answered:
                    response_time = res.time - req.sent_time
                    ip_addr = res.sprintf('%IP.src%')
                    self.udp_results_text.insert(tk.END, f"IP: {ip_addr} - Response Time: {response_time:.3f}s\n")

        # Start the scan thread
        thread = threading.Thread(target=scan_thread)
        thread.start()

    def tcp_ping_scan(self):
        """
        This function performs a TCP Ping Scan. It retrieves the IP range and scan type from the GUI,
        then starts a new thread to perform the scan.

        :return: None
        """
        # Get the IP range from the GUI
        ip_range = self.tcp_ip_range_entry.get()
        # Get the scan type from the GUI and convert it to an integer
        scan_type = ["SYN Scan", "ACK Scan", "Null Scan", "XMAS Scan", "FIN Scan"].index(
            self.tcp_scan_type_var.get()) + 1
        # Clear the results text box in the GUI
        self.tcp_results_text.delete("1.0", tk.END)

        def scan_thread():
            """
            This function performs the TCP Ping Scan in a separate thread. It sends TCP packets with different flags
            based on the scan type and updates the results text box in the GUI with the results.

            :return: None
            """
            # Create the TCP packet to send based on the scan type
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

            # Send the TCP packet and collect the responses
            answered, unanswered = sr(ping, timeout=2, verbose=0)
            # Update the results text box in the GUI with the results
            self.tcp_results_text.insert(tk.END, f"\nFinished sending {len(unanswered) + len(answered)} packets.\n")
            if len(answered) > 0:
                self.tcp_results_text.insert(tk.END, ".\\" * len(answered) + "\n")
            self.tcp_results_text.insert(tk.END,
                                         f"Received {len(answered) + len(unanswered)} packets, got {len(answered)} answers, remaining {len(unanswered)} packets\n")

            # If no responses were received, update the results text box in the GUI
            if len(answered) == 0:
                self.tcp_results_text.insert(tk.END, "No responses received for TCP Ping Scan.\n")
            else:
                # If responses were received, update the results text box in the GUI with the IP addresses of the hosts
                self.tcp_results_text.insert(tk.END, "Alive Hosts:\n")
                for req, res in answered:
                    response_time = res.time - req.sent_time
                    ip_addr = res.sprintf('%IP.src%')
                    tcp_flags = res[TCP].flags
                    self.tcp_results_text.insert(tk.END,
                                                 f"IP: {ip_addr} - TCP Flags: {tcp_flags} - Response Time: {response_time:.3f}s\n")

        # Start the scan thread
        thread = threading.Thread(target=scan_thread)
        thread.start()

    def ip_protocol_ping_scan(self):
        """
        This function performs an IP Protocol Ping Scan. It retrieves the IP range and protocols from the GUI,
        then starts a new thread to perform the scan.

        :return: None
        """
        # Get the IP range from the GUI
        ip_range = self.ip_ip_range_entry.get()
        # Get the protocols from the GUI and convert them to integers
        protocols = [int(p) for p in self.ip_protocols_var.get().split()]
        # Clear the results text box in the GUI
        self.ip_results_text.delete("1.0", tk.END)

        def scan_thread():
            """
            This function performs the IP Protocol Ping Scan in a separate thread. It sends packets for each protocol
            and updates the results text box in the GUI with the results.

            :return: None
            """
            # Loop over each protocol
            for protocol in protocols:
                # Create the packet to send
                ping = IP(dst=ip_range, proto=protocol)
                # Send the packet and collect the responses
                answered, unanswered = sr(ping, timeout=2, verbose=0)
                # Update the results text box in the GUI with the results
                self.ip_results_text.insert(tk.END,
                                            f"\nFinished sending {len(unanswered) + len(answered)} packets for protocol {proto2str(protocol)}.\n")
                if len(answered) > 0:
                    self.ip_results_text.insert(tk.END, ".\\" * len(answered) + "\n")
                self.ip_results_text.insert(tk.END,
                                            f"Received {len(answered) + len(unanswered)} packets, got {len(answered)} answers, remaining {len(unanswered)} packets\n")

                # If no responses were received, update the results text box in the GUI
                if len(answered) == 0:
                    self.ip_results_text.insert(tk.END, f"No responses received for protocol {proto2str(protocol)}.\n")
                else:
                    # If responses were received, update the results text box in the GUI with the IP addresses of the hosts
                    self.ip_results_text.insert(tk.END, f"Alive Hosts for protocol {proto2str(protocol)}:\n")
                    for req, res in answered:
                        ip_addr = res.sprintf('%IP.src%')
                        self.ip_results_text.insert(tk.END, f"{ip_addr}\n")

        # Start the scan thread
        thread = threading.Thread(target=scan_thread)
        thread.start()


if __name__ == "__main__":
    app = HostDiscoveryTool()
