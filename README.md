# VulnerMapper

This is a penetration testing program, written in shell script, to automate the scanning, enumeration and vulnerability assessment of local network devices.

The brute-force attack will take a long time. If you just want to test if this program works, set your user and password as "kali" for the hosts in the local target network.

## MODULES

INSTALL(): automatically installs relevant applications and creates relevant directories

CONSOLE(): collects user input for session name and network range, creates new directory, and executes the subsequent core functions

NMAP_SCAN(): uses Nmap to scan for ports and services, and saves information into directory

NMAP_ENUM(): uses Nmap Scripting Engine (NSE) to conduct further enumeration of hosts, based on scan results

SEARCHSPLOIT_VULN(): uses Searchsploit to identify vulnerabilities and potential exploits based on the enumeration results

HYDRA_BRUTE(): uses Hydra to find weak passwords used in the network's login services, based on scan results

LOG(): shows the user the collated results of NMAP_SCAN(), NMAP_ENUM(), SEARCHSPLOIT_VULN(), HYDRA_BRUTE() and EXPLOIT() 

## EXECUTION

Execute VulnerMapper.sh with bash to start the script.

    $ bash VulnerMapper.sh

## INSTALL()

The user will be asked to either install relevant applications or skip to the console. if applications are already installed previously.


## CONSOLE()

After installation or skipping installation, the user will arrive at a console for the user to key in the session name and network range. After that, the core modules will be executed on the network range.

The subdirectory for the session and then the network range will be created to store output files.

## NMAP_SCAN()

The program will use nmap to scan for open ports and services in the target range and log results. This will take a long time if you have a large range of hosts.


## NMAP_ENUM(

The program will use Nmap Scripting Engine (NSE) to to conduct further enumeration of hosts, based on scan results.

## SEARCHSPLOIT_VULN()

The program will use Searchsploit to identify vulnerabilities and potential exploits based on enumeration results.

## HYDRA_BRUTE()

The program will use Hydra to find weak passwords used in the network's login services, based on the vulnerability results.


## LOG()

The program will aggregate the collated results of NMAP_SCAN(), NMAP_ENUM(), SEARCHSPLOIT_VULN() and HYDRA_BRUTE() after their execution. The identified exploits require manual exploitation.


The program will generate "Vulnerability Map" reports on the terminal and inside the subdirectories of the individual hosts. For this example, the SSH service version was detected. The login username and password are also cracked as "kali".




Output files are channelled away to different subdirectories based on their hosts for clean look.



Raw output can be accessed inside the subdirectory.




## END

Press 'y' to return to the console (Installation Check) to conduct another mapping session or on another range.

Press any other key to exit.





