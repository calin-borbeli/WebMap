# WebMap
Network reconnaissance tool written in python3 and designed for scanning and enumerating web servers

![image](https://github.com/calin-borbeli/WebMap/assets/47243256/f55796ce-9363-449a-bbbe-ca6b83e44512)


## Run
To run the script the user has to enter the following command including the required –n flag and the network range to be scanned:

`python3 webmap.py -n` [network range to be scanned]

Example:

`python3 webmap.py -n 10.0.2.0/24`

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

`python3 webmap.py -h [--help]`

## Results

Once you run the command `python3 webmap.py -n` [network range to be scanned] you may be asked for your password. Webmap requires sudo permissions to run. However, you don't need to use sudo in front of the command but you may need to enter your password if you haven’t run the sudo command for a while.

### Network Discovery
The script starts by scanning the network for active devices using netdiscover and then it displays the list of active devices ip addresses as shown below:

![image](https://github.com/calin-borbeli/WebMap/assets/47243256/fe2361e1-8867-4194-a482-d096e6b8c6a4)

### OS Identification
Next, the script identifies the operating systems of the active devices using ping and then displays the list of devices possible operating systems as shown below:

![image](https://github.com/calin-borbeli/WebMap/assets/47243256/7ddca3e3-66b3-4ca5-a851-2818f5fda165)

### Open Ports Identification
Next, the script scans and identifies any open ports on each active device using nmap, and then displays the open ports for the active device as shown below:

![image](https://github.com/calin-borbeli/WebMap/assets/47243256/32ab4f98-78bb-4884-b5e4-c7732355c173)

### Web Enumeration
Next, the script checks if any device has port 80 open, and if it does then it conducts a web enumeration using gobuster and identifies common directories and files and outputs the list of directories and files found on the web server. The list is presented as links with the handy option of being able to right click on the link and open the link directly in browser, as shown below:

![image](https://github.com/calin-borbeli/WebMap/assets/47243256/43ee997c-3bef-4f3d-8bdb-cb1bcdddef90)

The script finishes and returns to the terminal prompt.

