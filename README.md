# SARPDET
Simple ARP Spoofing Detection Tool
by Roberto Dillon/Adsumsoft 2023

Sarpdet uses the library scapy to sniff packets and extract the MAC and IP addresses of devices on the network. Do install scapy if needed with something like:

> pip install scapy

Sarpdet can be launched with the following command, specifying a log file and a time duration as parameters (the latter is optional):

> python sarpdet.py log_filename.csv --time 120

Do note that the wifi adapter needs to be in promiscuous mode to sniff packets and that admin rights on the local machine are required too.

How it works:
------------------------
When an ARP packet is intercepted, the tool checks whether the request is coming from a new machine (i.e. new MAC) or not. If the device has already been listed, i.e. its MAC is already in the Python dictionary detected_devices{} the tool is building by checking the network traffic, we may have a device attempting to establish itself as a MITM and a warning is printed out.

The tool logs all found devices, identified by their MAC and corresponding IP addresses, in a CSV file for later reference. 
The name of the file is an input parameter, along with the time, in seconds, we want our tool to run (default value is 60). 
Input parameters are handled via the argparse library.
