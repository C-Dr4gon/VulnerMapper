# VulnerMapper

> This is a penetration testing program, written in bash script for Linux, to map out the ports, services and vulnerabilities of local network devices. This is intended for the Scanning Phase in the Penetration Testing cycle.

> CONFIG: The brute-force attack will take a long time. If you just want to test if this program works, set your user and password as "kali" for the hosts in the local target network.

> 1. INITIATION: Execute VulnerMapper.sh with bash to start the script.

    $ bash VulnerMapper.sh

> 2. INSTALL(): The program will automatically install relevant applications.


> 3. CONSOLE(): The program will arrive at a console for the user to key in the session name and network range.


> 4. SCAN(): The program will use nmap and masscan to scan for open ports and services in the target range and log results.


> 5. NSE(): The program will use nmap scripting engine to to conduct further enumeration of hosts, based on scan results.


> 6. SEARCHSPLOIT(): The program will use searchsploit to find potential vulnerabilities based on service results


> 7. BRUTEFORCE(): The program will use hydra and medusa to find weak passwords used in the network's login services, based on the vulnerability results


> 8. LOG(): The program will show the user the collated results of SCAN(), NSE(), SEARCHSPLOIT(), and BRUTEFORCE() after their execution.

