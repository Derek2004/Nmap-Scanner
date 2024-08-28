#!/usr/bin/python3

# Importing the nmap module, which provides functions for network scanning
import nmap

# Creating an instance of the PortScanner class from the nmap module
scanner = nmap.PortScanner()


print("Welcome this is a simple nmap automation tool")
print("<----------------------------------------------->")

# Prompting the user to input th IP they want to scan
ip_address = input("Please input the IP address you want to scan: ")
print("The IP you entered is: ", ip_address)

 # Prompting the user to select the type of scan they want to perform
resp = input("""\nPlease enter the type of scan you want to run
             1)SYN ACK Scan
             2)UDP Scan
             3)Comprehensive Scan
             \n""")
print("You have selected the option", resp)

# Checking the user's selection and performing the corresponding scan
if resp == '1':
    # If the user selects option 1, perform a SYN ACK scan
    print("Nmap Version: ", scanner.nmap_version())

    # Scanning the specified IP address, scanning ports 1-1024 using a SYN scan
    scanner.scan(ip_address, '1-1024', '-v -sS')

    # Printing the scan information and the status of the IP address
    print(scanner.scaninfo())
    print("Ip status: ", scanner[ip_address].state())
    print("Protocols:", scanner[ip_address].all_protocols())
    
     # Checking if any TCP ports are open and printing them
    if 'tcp' in scanner[ip_address].all_protocols():
        print("Open Ports :", scanner[ip_address]['tcp'].keys())
    
    else:
        print("No open TCP Ports found")

elif resp == '2':
    # If the user selects option 2, perform a UDP scan
    print("Nmap Version :", scanner.nmap_version())

    # Scanning the specified IP address, scanning ports 1-1024 using a UDP scan
    scanner.scan(ip_address, '1-1024', '-v -sU')
    
    # Printing the scan information and the status of the IP address
    print(scanner.scaninfo())
    print("IP Status :", scanner[ip_address].state())
    print("Protocol :", scanner[ip_address].all_protocols())

    # Checking if any UDP ports are open and printing them
    if 'udp' in scanner[ip_address].all_protocols():
        print("Open Ports :", scanner[ip_address]['udp'].keys())

    else:
        print("No open UDP ports were found")

elif resp == '3':
    # If the user selects option 3, perform a comprehensive scan
    print("Nmap Version:", scanner.nmap_version())

    # Scanning the specified IP address, scanning ports 1-1024 using a comprehensive scan 
    scanner.scan(ip_address, '1-1024', '-v -sS -sV -sC -A -O')

    # Printing the scan information and the status of the IP address
    print("Scan Info:", scanner.scaninfo())
    print("IP Status:", scanner[ip_address].state())
    print("Protocols:", scanner[ip_address].all_protocols())

    # Checking if any TCP ports are open and printing them
    if 'tcp' in scanner[ip_address].all_protocols():
        print("Open Ports :", scanner[ip_address]['tcp'].keys())
    
    # If the user enters an invalid option, display an error message
else :
    print("Please enter a valid input")
