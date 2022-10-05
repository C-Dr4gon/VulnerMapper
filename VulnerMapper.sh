#!/bin/bash

###########################
### VULNERMAPPER FUNCTIONS
###########################

# INSTALL(): automatically installs relevant applications and creates relevant directories
# CONSOLE(): collects user input for session name and network range, creates new directory, and executes the subsequent core functions
# NMAP_SCAN(): uses Nmap to scan for ports and services, and saves information into directory
# NMAP_ENUM(): uses Nmap Scripting Engine (NSE) to conduct further enumeration of hosts, based on scan results
# SEARCHSPLOIT_VULN(): uses Searchsploit to find potential vulnerabilities based on enumeration results
# HYDRA_BRUTE(): uses Hydra to find weak passwords used in the network's login services, based on the vulnerability results
# LOG(): shows the user the collated results of NMAP_SCAN(), NMAP_ENUM(), SEARCHSPLOIT_VULN(), and HYDRA_BRUTE() after their execution 

#####################
### INSTALL FUNCTION
#####################

### DEFINITION

function INSTALL()
{
	### START
	# let the user know that VulnerMapper is starting
	echo " "
	echo "[*] VulnerMapper is starting..."
	echo " "
	echo "[*] Installing and updating applications on your local computer..."
	echo " "
	echo "[*] Creating new directory: ~/VulnerMapper..."
	echo " "
	
	### APT UPDATE
	# update APT packages
	sudo apt-get -y update
	sudo apt-get -y upgrade
	sudo apt-get -y dist-upgrade
	
	### DIRECTORY
	# create a directory to contain output files later
	cd ~
	mkdir VulnerMapper
	cd ~/VulnerMapper
	echo "[+] Directory created: ~/VulnerMapper"
	echo " "
	
	# WORDLIST CONFIGURATION
	echo "[*] Configuring Wordlists..."
	sudo apt-get -y install wordlists
	cd /usr/share/wordlists
	sudo gunzip rockyou.txt.gz
	sudo cp rockyou.txt ~/VulnerMapper/wordlist.txt
	cd ~/VulnerMapper
	sudo sed -i '1i kali' wordlist.txt
	WordList=~/VulnerMapper/wordlist.txt
	echo "[+] Wordlist created: ~/VulnerMapper/wordlist.txt"
	echo " "
	cd ~/VulnerMapper
	
  	### FIGLET INSTALLATION
	# install figlet for aesthetic purposes
	# create a directory for downloading the figlet resources
	mkdir figrc
	cd ~/VulnerMapper/figrc
	sudo apt-get -y install figlet
	# install cybermedium figlet font; credits: http://www.figlet.org
	wget http://www.jave.de/figlet/fonts/details/cybermedium.flf
	cd ~/VulnerMapper
	
	### CORE APPLICATIONS INSTALLATION
	# install relevant applications
	sudo apt-get -y install nmap
	sudo apt -y install exploitdb
	sudo apt-get -y install hydra
	
	### END
	# let the user know applications are installed
	echo " "
	echo "[+] Applications installed and updated."
	echo "	"
}

### EXECUTION
# call the INSTALL function
INSTALL

#######################
### NMAP_SCAN FUNCTION
#######################

### DEFINITION

function NMAP_SCAN()
{ 
        ### START
        echo " "
        echo "[*] Executing NMAP_SCAN Module....."
        echo " "
        echo "[*] Scanning $netrange on ports 0-65535...(This may take a long time)"
        echo " "
    
        ## SCANNING
        # execute nmap scan with -Pn flag to avoid firewall
	# save the scan output in greppable format for text manipulation later
        sudo nmap -Pn -T4 -v -oG -p0-65535 $netrange > nmap_scan.txt
        
        ### END
        # let user know that the scan is done
        echo " "
        echo "[+] Nmap Scan has been executed."
        echo " "
}

#######################
### NMAP_ENUM FUNCTION
#######################

### DEFINITION

function NMAP_ENUM()
{
	### START
        echo " "
        echo "[*] Executing NMAP_ENUM Module....."
        echo " "
        echo "[*] Parsing output data from NMAP_SCAN Module..."
        echo " "
	echo "[*] Executing Nmap Scripting Engine Enumeration on open ports and services for $netrange...(This may take a long time)"
	echo " "
	
	### HOST FILTERING
	# manipulate greppable output to create list of open hosts
	echo $(cat nmap_scan.txt | grep Ports: | awk '{print $2}') > nmap_openhosts.lst

	### ENUMERATION LOOP
	# for each open host, filter and manipulate the data of open ports, then pass it as input for a standard NSE script to enumerate the host
	
	for openhost in nmap_openhosts.lst
	do
		### TEXT MANIPULATION
		# filter the single-line data of the open host from the greppable scan output
		echo $(cat nmap_scan.txt | grep Ports: | grep $openhost) > linedata.txt
		
		### TEXT MANIPULATION
		# extract a list of open ports by susbtituting space with line break, then filtering the port numbers
		echo $(cat linedata.txt | tr " " "\n" | grep , | awk '{print $2}' | awk -F/ '{print $1}') > openports.lst
		
		### TEXT MANIPULATION
		# change the vertical list of ports to a single string variable, divided by commmas, for input later
		openports_var = echo "$(cat openports.lst | tr "\n" ",")
		
		### ENUMERATION
		# execute standard NSE script (-sC) for the open ports for the open host
		sudo nmap -sC -p$openports_var -T4 $openhost -oX "$openhost"_enum.xml
		
		### CLEAN-UP
		# remove the temporary lists to avoid overcrowding the directory (especially for large network range and multiple open ports)
		rm linedata.txt
		rm openports.lst
	done
	
	### END
        # let user know that the enumeration is done
        echo " "
        echo "[+] Nmap Scripting Engine Enumeration has been executed."
        echo " "
}

###############################
### SEARCHSPLOIT_VULN FUNCTION
###############################

### DEFINITION

function SEARCHSPLOIT_VULN()
{
	### START
        echo " "
        echo "[*] Executing SEARCHSPLOIT_VULN Module....."
        echo " "
        echo "[*] Parsing output data from NMAP_ENUM Module..."
        echo " "
	echo "[*] Executing Searchsploit Vulnerability Detection on enumerated hosts and services......(This may take a long time)"
	echo " "
	
	### VULNERABILITY DETECTION
	for i in {}enum.xml
	sudo searchsploit --*_enum.xml
	
	### END
        # let user know that the enumeration is done
        echo " "
        echo "[+] Searchsploit Vulnerability Detection has been executed."
        echo " "
}

#########################
### HYDRA_BRUTE FUNCTION
#########################

### DEFINITION

function HYDRA_BRUTE()
{
        ### START
        echo " "
        echo "HYDRA BRUTE-FORCE ATTACK"
        echo " "
        echo "[!] Enter IP Address of Target Host:"
        read IP
        echo " "
        cd ~/NetTester
        
        ### BRUTE FORCE ATTACK
        sudo hydra -f -L $WordList -P WordList $IP $Protocol -t 4 -vV > hydraoutput.txt
	
	sudo medusa -h $IP -U $WordList -P WordList -M $Protocol
        
        ### LOGGING
        # call the LOG function to append elements of hydraoutput.txt into netlog.log
        LOG
        # let user know about the number and details of cracked users
        echo " "
        echo "$(cat hydraoutput.txt | grep host: | wc -l) [+] CRACKED USERS: (Format: <username> <password>)"
        echo "$(cat hydraoutput.txt | grep host: | awk '{print $5 $7}')"
        echo " "
        
        ### END
        # remove the hydraoutput.txt files after use
        rm hydraoutput.txt
        # let user know that the attack is done
        echo " "
        echo "[+] Hydra SMB Brute-Force Attack has been executed and logged at ~/NetTester/log.log."
        echo " "
}

#################
### LOG FUNCTION
#################

### DEFINITION

function LOG()
{ 
	### NMAP LOGGING
	# test if nmapoutput.txt exists
        cd ~/NetTester
	if [ -f ~/NetTester/nmapoutput.txt ]
	then
		# include date, time, IPs, attack type and used arguments in log
		DateTime="$(date +%F)_$(date +%X | awk '{print $1}')"
		AttackType="NmapPortScan"
		Arg="[sudo nmap -Pn $IP]"
		NumOpenPorts="$(cat nmapoutput.txt | grep open | wc -l)"
		# append filtered data into log.log
		echo "$DateTime $IP $AttackType $Arg [$NumOpenPorts Open Ports"] >> log.log
		        # let user know about the number and details of open ports 
       		echo " "
        	echo "$(cat nmapoutput.txt | grep open | wc -l) [+] OPEN PORTS:"
        	echo "$(cat nmapoutput.txt | grep open | awk '{print $1}')"
        	echo " "
	fi
	
	### MASSCAN LOGGING
	# test if masscanoutput.txt exists
        cd ~/NetTester
	if [ -f ~/NetTester/masscanoutput.txt ]
	then
		# include date, time, IPs, attack type and used arguments in log
		DateTime="$(date +%F)_$(date +%X | awk '{print $1}')"
		AttackType="MasscanPortScan"
		Arg="[sudo masscan $IP -p'$Ports']"
		NumOpenPorts="$(cat masscanoutput.txt | grep open | wc -l)"
		# append filtered data into log.log
		echo "$DateTime $IP $AttackType $Arg [$NumOpenPorts Open Ports]" >> log.log
	fi
	
	### MSF LOGGING
	# test if msfoutput.txt exists
        cd ~/NetTester
	if [ -f ~/NetTester/msfoutput.txt ]
	then
		# include date, time, IPs, attack type and used arguments in log
		DateTime="$(date +%F)_$(date +%X | awk '{print $1}')"
		AttackType="MSFSMBBruteForceAttack"
		Arg="[sudo msfconsole -r msfscript.rc]"
		NumCrackedUsers="$(cat msfoutput.txt | grep Success: | wc -l)"
		# append filtered data into log.log
		echo "$DateTime $IP $AttackType $Arg [$NumCrackedUsers Cracked Users"] >> log.log
	fi
	
	# HYDRA LOGGING
	# test if hydraoutput.txt exists
        cd ~/NetTester
	if [ -f ~/NetTester/hydraoutput.txt ]
	then
		# include date, time, IPs, attack type and used arguments in log
		DateTime="$(date +%F)_$(date +%X | awk '{print $1}')"
		AttackType="HydraSMBBruteForceAttack"
		Arg="[sudo hydra -L $UserList -P $PassList $IP smb -vV]"
		NumCrackedUsers="$(cat hydraoutput.txt | grep host: | wc -l)"
		# append filtered data into log.log
		echo "$DateTime $IP $AttackType $Arg [$NumCrackedUsers Cracked Users]" >> log.log
	fi
}

###################
# CONSOLE FUNCTION
###################

### DEFINITION

function CONSOLE()
{
	### START
	# display figlet for aesthetics, with short description of program
	figlet -c -f ~/VulnerMapper/figrc/cybermedium.flf -t "VULNERMAPPER"
	echo " "
	echo "[*] This program is for mapping vulnerabilities of all hosts within a local network. Please use for penetration testing and education purposes only."
	echo " "
	echo "[!] Press Ctrl-C to exit."
	echo " "
	
	### SESSION NAME INPUT
	read -p "[!] Enter Session Name: " session
	cd ~/VulnerMapper
	mkdir $session
	cd ~/VulnerMapper/$session
	echo " "
	echo "[+] Directory created: ~/VulnerMapper/$session"
	echo " "
	
	### NETWORK RANGE INPUT
	read -p "[!] Enter Target Network Range (e.g. 192.168.235.0/24): " netrange
	echo " "
	net=echo $(echo '$netrange' | awk -F/ '{print $1}')"
	cd ~/VulnerMapper/$session
	mkdir $net
	cd ~/VulnerMapper/$session/$net
	echo " "
	echo "[+] Directory created: ~/VulnerMapper/$session/$net"
	echo " "
	echo "[*] Mapping the range $range......"
	echo " "
	
	### CORE EXECUTION
	# call the core functions to map the specified local network range
	SCAN
	NSE_ENUM
	SEARCHSPLOIT
	BRUTEFORCE
	LOG
	
	### END
	# force a pause before triggering the loop to allow the user to focus on the results
	echo " "
	echo "[!] Press any key to return to the console."
}

### EXECUTION
# call the CONSOLE function through while-true loop to return user to the console after every execution
while true 
do
CONSOLE
done
