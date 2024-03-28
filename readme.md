# Host Discovery Tool

The Host Discovery Tool is a graphical application designed for network administrators and cybersecurity professionals. It facilitates various types of network scans to discover active hosts on a network. Utilizing the Scapy library, this tool supports ARP Ping Scan, ICMP Ping Scan, UDP Ping Scan, TCP Ping Scan, and IP Protocol Ping Scan.

## Features

- **Graphical User Interface**: Easy-to-use GUI built with Tkinter.
- **Multiple Scan Types**:
  - ARP Ping Scan: Discover hosts using ARP requests.
  - ICMP Ping Scan: Discover hosts using ICMP Echo requests.
  - UDP Ping Scan: Discover hosts by sending UDP packets to a specified port.
  - TCP Ping Scan: Discover hosts using TCP packets with various flags.
  - IP Protocol Ping Scan: Discover hosts by probing different IP protocols.
- **Customizable Parameters**: Each scan type allows for the input of custom parameters such as IP range, port, and protocols.
- **Real-time Results Display**: Scanning results are displayed in real-time within the application.

## Installation

To use the Host Discovery Tool, you need to have Python installed on your system along with the Tkinter and Scapy libraries. 

1. **Install Python**: Download and install Python from [python.org](https://www.python.org/).

2. **Install Dependencies**: Open a terminal or command prompt and run the following command to install Scapy:
   ```bash
   pip install scapy
   ```

## Usage

1. Clone this repository or download the `main.py` file.
2. Run the script using Python:
   ```bash
   python main.py
   ```
3. The application window will open. Select the type of scan you wish to perform from the tab menu.
4. Enter the required parameters for your selected scan type (e.g., IP range, port number).
5. Click the "Scan" button to start the scan. Results will be displayed in the text area within each tab.

## Contributing

Contributions to the Host Discovery Tool are welcome. Please feel free to fork the repository, make improvements, and submit pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for educational and ethical use only. Use of this tool for unauthorized testing or malicious activities is not condoned and may be illegal in your jurisdiction.
