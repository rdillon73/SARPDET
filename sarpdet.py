import csv
import argparse
from scapy.all import ARP, Ether, sniff


def print_intro():
    print("========================================")
    print("=                                      =")
    print("=            sarpdet v.0.1.0           =")
    print("=       Simple ARP Detection Tool      =")
    print("=         by Roberto Dillon            =")
    print("=     https://github.com/rdillon73     =") 
    print("=                                      =") 
    print("========================================")

def detect_arp_spoofing(log_filename, sniff_duration=60):
    detected_devices = {}

    def arp_monitor_callback(pkt):
        if ARP in pkt and Ether in pkt:
            source_mac = pkt[Ether].src
            source_ip = pkt[ARP].psrc

            if source_mac not in detected_devices:
                detected_devices[source_mac] = source_ip
            else:
                if detected_devices[source_mac] != source_ip:
                    print(f"Warning: ARP spoofing detected for MAC {source_mac} (IP {source_ip})")

    print("ARP Spoofing Detection Started...")

    # Start sniffing ARP packets in the network with a timeout; store=0 means packets are not stored in memory
    sniff(prn=arp_monitor_callback, filter="arp", store=0, timeout=sniff_duration)

    # Write the results to a CSV log file; change mode to 'a' to append data if you are using the same log file (running this as a cronjob, perhaps?) 
    with open(log_filename, mode='w', newline='') as log_file:
        fieldnames = ['MAC Address', 'IP Address']
        writer = csv.DictWriter(log_file, fieldnames=fieldnames)
        writer.writeheader()
        for mac, ip in detected_devices.items():
            writer.writerow({'MAC Address': mac, 'IP Address': ip})

    print(f"Detection completed. Results saved to '{log_filename}'.")


if __name__ == "__main__":
    print_intro()

    parser = argparse.ArgumentParser()
    parser.add_argument("log_filename", help="Name of the CSV log file to save results")
    parser.add_argument("--time", type=int, default=60,
                        help="Duration (in seconds) for ARP packet sniffing (default: 60 seconds)")
    args = parser.parse_args()

    detect_arp_spoofing(args.log_filename, args.time)