# WebMap
Network reconnaissance tool written in python3 and designed for scanning and enumerating web servers

## Run
To run the script the user has to enter the following command including the required –n flag and the network range to be scanned:

`python3 webmap.py -n` [network range to be scanned]

![image](https://github.com/calin-borbeli/WebMap/assets/47243256/71223690-8b57-4fc4-8f9e-431829edfe2a)

Example:

`python3 webmap.py -n 10.0.2.0/24`

![image](https://github.com/calin-borbeli/WebMap/assets/47243256/910a22bc-a803-426c-bc1d-a95844673b43)

## Requirements

### Permissions
Webmap requires sudo permissions to run. However, the user doesn't need to use sudo in front of the command but may need to enter their password.

### Dependencies
Webmap uses netdiscover, ping, nmap and gobuster combined into one single script as a 'one stop shop' approach that will run everything in one go instead of having to manually enter the commands and run each tool individually.
        
This approach improves efficiency and is less prone to errors.
        
Gobuster does not natively scan directories recursively but it only scans the current directory.
However, webmap uses gobuster recursively thus being able to go deep into the directory structure and list all the subdirectories.
 
Webmap requires the following dependencies:
python3, netdiscover, python-nmap, gobuster

Ensure that all dependencies are installed before running the script.

### Errors Fixes
Missing dependencies errors fixes:

- if python3 is not istalled use:

  `sudo apt install python3`
  
- if netdiscover is not installed use:

  `sudo apt install netdiscover`

- if python-nmap module is not installed use:

  `pip install python-nmap`

- if gobuster is not installed use:

  `sudo apt install gobuster`

There is a short help section that provides users with a description of the script, the required dependencies and how to install any missing dependencies.
Users can access the help section using the familiar help flags `-h [--help]`:
python3 webmap.py -h [--help] as shown below:
 
