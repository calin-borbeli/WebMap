#!/usr/bin/python
import sys
import os
import subprocess
import re
import nmap
from subprocess import Popen, PIPE
from termcolor import colored, cprint


def run_web_map(net):  # Runs the main function

    def net_discover(net):
        cprint(
            f"\nScanning the network {net} for any active devices:\n", "white", attrs=["bold"])
        print("Please Wait...\n")
        try:
            # Runs the netdiscover command and captures the output
            data = subprocess.check_output(
                ['sudo', 'netdiscover', '-P', '-N', '-r', net])
            # Converts the output to a string and splits it at each line
            content = data.decode('utf-8').split('\n')
            if "ERROR: Network range must be 0.0.0.0/8 , /16 or /24" in data.decode('utf-8'):
                print("ERROR: Network range must be 0.0.0.0/8 , /16 or /24")
                sys.exit(1)
            # output=["ip","mac","count","len","vendor"] # This is if we need to output other info
            output = ["ip"]  # This will only output the ip
            output = [key for key in output if key in (
                "ip", "mac", "count", "len", "vendor")]

            results = []  # Creates empty list for results

            if len(content) != 0:  # Checks if the output has content
                for line in content:
                    # Searches for output params in each line of the content and creates the groupnames
                    params = re.search(r"\s?(?P<ip>\d+\.\d+\.\d+\.\d+)"
                                       r"\s+(?P<mac>[a-fA-F0-9:]{17})"
                                       r"\s+(?P<count>\d+)"
                                       r"\s+(?P<len>\d+)"
                                       r"\s+(?P<vendor>.*)",
                                       line)
                    if params:  # Checks if the search found any params and
                        # puts the params into a dictionary with the groupname
                        # as keys and the matched string as the value for that key
                        params = params.groupdict()
                        # Appends to the results list, the params as key/value pairs for the keys in output
                        results.append({key: params[key] for key in output})
            else:
                print(f"There are no active devices on the network {net}.\n")
                return
            ips = []
            for device in results:  # Runs through each active device and prints ip address
                ip = device["ip"]
                cprint((f"{indent}Active host ip {ip}\n"),
                       "green", attrs=["bold"])
                ips.append(ip)
            # Checks if there are any active ips
            if len(ips):
                return ips
            else:
                sys.exit(
                    f"There are no active devices on the network {net}.\n")

        except subprocess.CalledProcessError as e:
            # Handles any errors that occur during the execution of the netdiscover command
            print(f"An error occurred: {e}")
            sys.exit(1)

    def os_discover(ips, ping_count):
        cprint("\nIdentifying possible operating systems on active devices:\n",
               "white", attrs=["bold"])
        print("Please Wait...\n")
        new_ips = []  # Prepares a new ips list to discard non-responding ips
        for ip in ips:  # Runs through each ip
            data = ""
            # Runs ping command and captures the output
            output = Popen(
                ["ping", "-c", str(ping_count), ip], stdout=PIPE, encoding="utf-8")
            for line in output.stdout:
                data = data + line  # Converts the output line by line into a single string
            if "ttl" or "TTL" in data:
                # Creates a new ips list to discard non-responding ips
                new_ips.append(ip)
                # Searches for ttl and determie the OS
                ttl = re.search(r"(?i)\s+(ttl=(?P<ttl>\d+))", data)
                ttl = int(ttl.groupdict()["ttl"])
                if ttl == 64:
                    cprint(
                        (f"{indent}Active host ip {ip} ttl={ttl} possible OS: \"Linux\"\n"), "yellow", attrs=["bold"])
                elif ttl == 128:
                    cprint(
                        (f"{indent}Active host ip {ip} ttl={ttl} possible OS: \"Windows\"\n"), "cyan", attrs=["bold"])
                else:
                    cprint(
                        (f"{indent}Active host ip {ip} ttl={ttl} possible OS: \"Other\"\n"), "magenta", attrs=["bold"])
            else:
                print(f"IP: {ip} not responding.\n")
        # Checks if there are any responding ips
        if len(new_ips):
            return new_ips
        else:
            sys.exit(f"There are no reponding ips on the network {net}.\n")

    def port_scan(new_ips):
        cprint("\nScanning all active devices for open ports in the first 1000 ports\n",
               "white", attrs=["bold"])
        print("LEGEND")
        print("-"*68)
        cprint("Blue    ->  Filtered Ports", "cyan", attrs=["bold"])
        cprint("Green   ->  Open Ports", "green", attrs=["bold"])
        cprint("Orange  ->  Open 'Interesting' Ports",
               "yellow", attrs=["bold"])
        cprint("Red     ->  Open 'Very Interesting' Ports",
               "red", attrs=["bold"])
        print("-"*68)
        print()
        try:
            # Tries to run the namp PortScanner method and assigns it to a variable
            ip_scan = nmap.PortScanner()
        except nmap.PortScannerError:
            print('Nmap not found', sys.exc_info()[0])
            sys.exit(1)
        except:
            print("Unexpected error:", sys.exc_info()[0])
            sys.exit(1)
        web_ips = []  # Creates a web ips list for the web servers ips
        for new_ip in new_ips:
            cprint(
                f"\n{indent}Scanning for open ports host ip {new_ip}\n", "white", attrs=["bold"])
            print(f"{indent}Please Wait...\n")
            # Runs the nmap scan method for the first 1000 ports
            ip_scan.scan(new_ip, '1-1000', '-Pn')
            # Checks if there are any protocols found
            if len(ip_scan[new_ip].all_protocols()):
                # Creates the table header
                print(indent + "PORT".ljust(16, " ") + "PROTOCOL".ljust(16, " ") +
                      "STATUS".ljust(16, " ") + "SERVICE".ljust(16, " "))
                print(indent + "-" * 64)
                # For each protocol we are getting info for each port
                for protocol in ip_scan[new_ip].all_protocols():
                    for port in ip_scan[new_ip][protocol].keys():
                        status = ip_scan[new_ip][protocol][port]['state']
                        service = ip_scan[new_ip][protocol][port]['name']
                        # Concatenates all info into one string variable
                        port_info = indent + str(port).ljust(
                            16, " ") + protocol.ljust(16, " ") + status.ljust(16, " ") + service.ljust(16, " ")
                        # Applies different colours based on the legend
                        if status == "filtered":
                            cprint(port_info, "cyan", attrs=["bold"])
                        elif service == "http":
                            cprint(port_info, "red", attrs=["bold"])
                            web_ips.append(new_ip)
                        elif service in ["ssh", "ftp", "telnet"]:
                            cprint(port_info, "yellow", attrs=["bold"])
                        else:
                            cprint(port_info, "green", attrs=["bold"])
                print(indent + "-" * 64)
                print()
            else:
                print(indent + "-" * 64)
                print(f"{indent}No open ports found on ip {new_ip}")
                print(indent + "-" * 64)
                print()
        # Checks if there are any web servers ips
        if len(web_ips):
            return web_ips
        else:
            sys.exit(f"There are no web servers on the network {net}.\n")

    def web_enum(web_ips, port):
        # Runs gobuster to find commmon directories and files
        # However, gobuster does not scan directories recursively
        # To overcome this limitation I created a recursive function
        # The function will call itself for each new directory found,
        # thus being able to go deeper into the directories structure
        def get_dir(url, wordlist, paths):
            directories = []  # Creates an empty directories list
            # Runs the gobuster and capturs the output
            output = Popen(["gobuster", "dir", "-u", url, "-w",
                           wordlist, "-z", "-q"], stdout=PIPE, encoding="utf-8")
            for line in output.stdout:
                # Checks the status for each line of the output and extracts the directory using regex
                if "(Status:" in line:
                    directory = re.search(
                        r"(?P<directory>\S+(?=\s+\(Status:))", line)
                    # Assigns the directory found
                    directory = directory.groupdict()["directory"]
                    # Removes the escaped characters
                    ansi_escape = re.compile(
                        r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                    directory = ansi_escape.sub('', directory)
                    # Adds the directory found to the url to create a full path
                    path = url + directory
                    directories.append(directory)
                    paths.append(path)
                    # Filters out files and hidden directories
                    if "." not in directory:
                        # Updates the url with the directory found to be used for the next iteration
                        url += directory
                        # Runs the get_dir function recursively
                        get_dir(url, wordlist, paths)
            return paths
        cprint("\nRevealing web servers common directories and files:\n",
               "white", attrs=["bold"])
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        for web_ip in web_ips:
            # url = f"http://{web_ip}:{port}" # Prepared for future proofing web servers set on other ports
            url = f"http://{web_ip}"
            print(f"{indent}Enumerating directories and files for {url}\n")
            print(f"{indent}Please Wait...\n")
            paths = [url]
            paths = get_dir(url, wordlist, paths)
            cprint(
                f"\nWeb enumeration for {url} completed!\n", "green", attrs=["bold"])
            # Checks if there are any common directories and files
            if len(paths):
                print(f"{indent}The following content has been found on {url}")
                print(
                    f"{indent}(Right+click on any link below and Open Link in browser)\n")
                paths.sort()
                for path in paths:
                    print(indent, end="")
                    cprint(path, "cyan", attrs=["bold", "underline"])
            else:
                print(f"{indent}No directories or files found.\n")
            print("\n")

    indent = 4
    indent *= " "
    ping_count = 3
    # Runs the netdiscover command
    ips = net_discover(net)
    # Runs the ping command
    new_ips = os_discover(ips, ping_count)
    # Runs nmap
    web_ips = port_scan(new_ips)
    # Runs gobuster on the web servers
    # Port number is hard coded to 80 as per the brief but in the future
    # I intend to get the port number based on the http service discovery
    # and run for any port that runs an http service not just port 80
    port = 80
    web_enum(web_ips, port)


# I only want to run the webmap function when the webmap.py is called
if __name__ == "__main__":
    # I want to accept arguments from the command line
    # So here I used the argparse module from python standard libray
    import argparse
    parser = argparse.ArgumentParser(
        prog="webmap.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=('''\
Webmap is a network reconnaissance tool written in python3 and designed for
scanning and enumerating web servers.
Written by: Calin Borbeli
___  ___  ___  ___ ________  _______   ___     ___      ___     ______   
   \    \   /    /         |        \     \       |        \          \  
    \      /    /    |____     |__   |     \      |     /   \     |__  | 
     \     \   /          |         \    |  \  /  |    /___  \        /  
        /     /      |_____    |__   |   |    /   |           \   |      
       /     /             |        /    |        |  /         \  |      

Webmap requires sudo permissions to run. You don't need to use sudo 
in front of the command but you may need to enter your password.

Webmap uses netdiscover, ping, nmap and gobuster combined into one single
script as a 'one stop shop' approach that will run everything in one go
instead of having to manually enter the commands and run each tool
individually.
        
This approach improves efficiency and is less prone to errors.
        
Gobuster does not natively scan directories recursively but it only
scans the current directory.
However, webmap uses gobuster recursively thus being able to
go deep into the directory structure and list all the subdirectories.
 
Webmap requires the following dependencies:
python3, netdiscover, python-nmap, gobuster

Make sure that all dependencies are installed before running the script.

Missing dependencies errors fixes:

- if python3 is not istalled use:
  sudo apt install python3
  
- if netdiscover is not installed use:
  sudo apt install netdiscover

- if python-nmap module is not installed use:
  pip install python-nmap

- if gobuster is not installed use:
  sudo apt install gobuster

'''
                     ))

    parser.add_argument(
        "-n", "--net", metavar="net",
        required=True, help="Enter the network range to be scanned. Network range must be ipv4 format 0.0.0.0/8 , /16 or /24"
    )

    args = parser.parse_args()

    # Oh Yes, I had lots of FUN doing this from scratch!!! Doesn't that look cool??? No, I didn't waste my time!
    cprint("___  ___  ___  ___ ________  _______   ___     ___      ___     ______   ",
           "green", attrs=["bold"])
    cprint("   \    \   /    /         |        \     \       |        \          \  ",
           "green", attrs=["bold"])
    cprint("    \      /    /    |____     |__   |     \      |     /   \     |__  | ",
           "green", attrs=["bold"])
    cprint("     \     \   /          |         \    |  \  /  |    /___  \        /  ",
           "green", attrs=["bold"])
    cprint("        /     /      |_____    |__   |   |    /   |           \   |      ",
           "green", attrs=["bold"])
    cprint("       /     /             |        /    |        |  /         \  |      ",
           "green", attrs=["bold"])

    cprint("\n----------------- SCANNING AND ENUMERATING WEB SERVERS -----------------",
           "green", attrs=["bold"])
    cprint("|                                                                      |",
           "green", attrs=["bold"])
    cprint("| Netdiscover, ping, nmap and gobuster combined into one single script |", "green")
    cprint("|                                                                      |",
           "green", attrs=["bold"])
    cprint("------------------------------------------------------------------------",
           "green", attrs=["bold"])
    print("by Calin Borbeli\n".rjust(72, " "))

    run_web_map(args.net)  # Call the function to run webmap
