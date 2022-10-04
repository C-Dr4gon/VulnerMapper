#!/bin/bash

###########################
### VULNERMAPPER FUNCTIONS
###########################

# INSTALL(): automatically installs relevant applications and creates relevant directories
# CONSOLE(): collects user input for session name and network range, creates new directory, and executes the subsequent core functions
# SCAN(): uses nmap and masscan to scan for ports and services, and saves information into directory
# NSE_ENUM(): uses nmap scripting engine to conduct further enumeration of hosts, based on scan results
# SEARCHSPLOIT(): uses searchsploit to find potential vulnerabilities based on enumeration results
# BRUTEFORCE(): uses hydra and medusa to find weak passwords used in the network's login services, based on the vulnerability results
# LOG(): shows the user the collated results of SCAN(), NSE(), SEARCHSPLOIT(), and BRUTEFORCE() after their execution 

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
	sudo apt-get -y install masscan
	sudo apt -y install exploitdb
	sudo apt-get -y install hydra
	sudo apt-get -y install medusa
	
	### END
	# let the user know applications are installed
	echo " "
	echo "[+] Applications installed and updated."
	echo "	"
}

### EXECUTION
# call the INSTALL function
INSTALL

##################
### SCAN FUNCTION
##################

### DEFINITION

function SCAN()
{ 
        ### START
        echo " "
        echo "[*] Initiating SCAN Module....."
        echo " "
        echo "[*] Executing Nmap and Masscan Scans on $range for ports 0-65535...(This will take a long time)"
        echo " "
    
        ## SCANNING
        # execute nmap scan with -Pn flag to avoid firewall
	# use nmap and masscan to scan all ports for the specified range
        sudo nmap -Pn -p0-65535 "$range" -T5> nmap_scan.txt
	sudo masscan -p0-65535 "$range" > masscan_scan.txt
        
        ### LOGGING
        # call the LOG function to append elements of nmap_scan.txt into log.txt
        LOG
       
        ### END
        # let user know that the scan is done
        echo " "
        echo "[+] Nmap Scan and Masscan Scan have been executed and logged at ~/VulnerMapper/$session/$range/log.txt."
        echo " "
}

######################
### NSE_ENUM FUNCTION
######################

### DEFINITION

function NSE_ENUM()
{
	### START
        echo " "
        echo "[*] Initiating NSE_ENUM Module....."
        echo " "
        echo "[*] Identifying open ports and services from scans..."
        echo " "
	echo "[*] Executing Nmap Scripting Engine Enumeration on open ports and services for $range...(This will take a long time)"
	echo " "
	
	### OPEN SERVICES DATA EXTRACTION
	$(cat nmapoutput.txt | grep open | awk '{print $3}') > nmap_services.lst
	
	### ENUMERATION
	# use a for-loop to iterate through the list of open services (port) identified by nmap
	# execute NSE enumeration for all available scripts for each open service
	# for the open service "domain", change it to "dns" for nse to process
	
	for i in nmap_services.lst
	do
		touch nmap_enumerated.txt
		
		if [ i == "domain" ]
		then
			j="dns"
			echo "[*] Executing Nmap Scripting Engine Enumeration on $j for $range...(This will take a long time)"
			nmap $range -sV --script="$j"* >> nmap_enumerated.txt
		else
			echo "[*] Executing Nmap Scripting Engine Enumeration on $i for $range...(This will take a long time)"
			nmap $range -sV --script="$i"* >> nmap_enumerated.txt
		fi
	done
	
	### END
        # let user know that the enumeration is done
        echo " "
        echo "[+] Nmap Scripting Engine Enumeration has been executed and logged at ~/VulnerMapper/$session/$range/log.txt."
        echo " "
}

##########################
### SEARCHSPLOIT FUNCTION
##########################

### DEFINITION

function SEARCHSPLOIT()
{
	### START
        echo " "
        echo "[*] Initiating SEARCHSPLOIT Module....."
        echo " "
        echo "[*] Identifying open ports and services from scans..."
        echo " "
	echo "[*] Executing Nmap Scripting Engine Enumeration on open ports and services for $range...(This will take a long time)"
	echo " "
}

########################
### BRUTEFORCE FUNCTION
########################

### DEFINITION

function BRUTEFORCE()
{
        ### START
        echo " "
        echo "HYDRA SMB BRUTE-FORCE ATTACK"
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
		echo "$DateTime $IP $AttackType $Arg [$NumOpenPorts Open Ports"] >> log.log
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
	read -p "[!] Enter Network Range (e.g. 192.168.235.0/24): " range
	cd ~/VulnerMapper/$session
	mkdir $range
	cd ~/VulnerMapper/$session/$range
	echo " "
	echo "[+] Directory created: ~/VulnerMapper/$session/$range"
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
