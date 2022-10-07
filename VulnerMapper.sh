#!/bin/bash

###########################
### VULNERMAPPER FUNCTIONS
###########################

# INSTALL(): automatically installs relevant applications and creates relevant directories
# CONSOLE(): collects user input for session name and network range, creates new directory, and executes the subsequent core functions
# NMAP_SCAN(): uses Nmap to scan for ports and services, and saves information into directory
# NMAP_ENUM(): uses Nmap Scripting Engine (NSE) to conduct further enumeration of hosts, based on scan results
# SEARCHSPLOIT_VULN(): uses Searchsploit to find potential vulnerabilities based on enumeration results
# HYDRA_BRUTE(): uses Hydra to find weak passwords used in the network's login services, based on scan results
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
# INSTALL

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
        sudo nmap -Pn -T4 -p0-65535 $netrange -oG nmap_scan.txt
        
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
	echo $(cat nmap_scan.txt | grep Ports: | grep open | awk '{print $2}') > nmap_openhosts.lst

	### ENUMERATION LOOP
	# for each open host, filter and manipulate the data of open ports, then pass it as input for a standard NSE script to enumerate the host
	
	for openhost in $(cat nmap_openhosts.lst)
	do
		### FILTERING: HOST
		echo " "
		echo "[*] Enumerating $openhost......"
		echo " "
		# filter the single-line data of the open host from the greppable scan output
		echo $(cat nmap_scan.txt | grep Ports: | grep open | grep $openhost) > linedata.txt
		
		### FILTERING: PORTS
		# extract a list of open ports by susbtituting space with line break, then filtering the port numbers
		echo $(cat linedata.txt | tr " " "\n" | grep open | awk -F/ '{print $1}') > openports.lst
		
		### TEXT MANIPULATION
		# change the vertical list of ports to a single string variable, divided by commmas, for input later
		portsstring=$(echo "$(cat openports.lst | tr " " ",")")
		
		### ENUMERATION
		# execute standard NSE script (-sC) for all for the open ports for the specified open host
		sudo nmap -sC -p $portsstring -T4 $openhost -oX $openhost_enum.xml
		
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
	
	### VULNERABILITY DETECTION LOOP
	# for each open host, filter and manipulate the data of enumerated services then pass it as input for Searchsploit to detect its vulnerabilities
	
	for openhost in $(cat nmap_openhosts.lst)
	do
		echo " "
		echo "[*] Detecting vulnerabilities on the services running on $openhost......"
		echo " "
		# execute Searchsploit on the enumerated XML file
		sudo searchsploit -x --nmap $openhost_enum.xml > $openhost_vuln.txt
	done
	
	### END
        # let user know that the detection is done
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
    echo "[*] Executing HYDRA_BRUTE Module....."
    echo " "
    echo "[*] Parsing output data from NMAP_SCAN Module..."
    echo " "
	echo "[*] Executing Hydra Brute-Force Attack on open hosts and ports......(This may take a long time)"
	echo " "
	
	### BRUTE-FORCE LOOP
	# for each open host, filter and manipulate the data of open ports, then pass it as input for a standard NSE script to enumerate the host
	
	for openhost in $(cat nmap_openhosts.lst)
	do
		### FILTERING: HOST
		echo " "
		echo "[*] Attacking $openhost......"
		echo " "
		# filter the single-line data of the open host from the greppable scan output
		echo $(cat nmap_scan.txt | grep Ports: | grep open | grep $openhost) > linedata.txt
		
		### FILTERING: PORTS
		# extract a list of open services by susbtituting space with line break, then filtering the port numbers
		echo $(cat linedata.txt | tr " " "\n" | grep open | awk -F/ '{print $5}') > openservices.lst		
      	
      	### BRUTE-FORCE ATTACK
		for openservice in $(cat openservices.lst)
		do
			echo "[*] Attacking $openservice on $openhost......"
			echo " "
			sudo hydra -f -L $WordList -P WordList $openhost $openservice -t 4 > hydra_brute.txt
			
			# remove output immediately is service is not supported by hydra
			if [ $(cat crackedpass.txt | grep ERROR | awk '{print $3}') == "service:" ]
			then
				rm hydra_brute.txt
				continue
				
			# if service supported, extract passwords from outputfile
			else
				echo "$(cat hydra_brute.txt | grep host: | awk '{print $7}')" >> '$openhost'_passwords.txt
				continue
			fi
		done
		
		### CLEAN-UP
		# remove the temporary lists to avoid overcrowding the directory (especially for large network range and multiple open ports)
		rm linedata.txt
		rm openservices.lst
		if [ -f hydra_brute.txt ]
		then
			rm hydra_brute.txt
		fi
		
	done
        
	### END
	# let user know that the attack is done
	echo " "
	echo "[+] Hydra Brute-Force Attack has been executed."
	echo " "
}

#################
### LOG FUNCTION
#################

### DEFINITION


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
	echo "[*] For quick testing, configure the target machines to have the user and password as 'kali'."
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
	net=$(echo $netrange | awk -F/ '{print $1}')
	mkdir $net
	cd ~/VulnerMapper/$session/$net
	echo " "
	echo "[+] Directory created: ~/VulnerMapper/$session/$net"
	echo " "
	echo "[*] Mapping the range $netrange......"
	echo " "
	
	### CORE EXECUTION
	# call the core functions to map the specified local network range
	NMAP_SCAN
	NMAP_ENUM
	SEARCHSPLOIT_VULN
	HYDRA_BRUTE
	# LOG
	
	### END
	# force a pause to allow the user to focus on the results
	echo " "
	read -p "[!] Enter any key to return to the console: " resume
	if [ ! -n "$resume" ]
	then
		continue
	else
		exit
	fi		
}

### EXECUTION
# call the CONSOLE function through while-true loop to return user to the console after every execution
while true 
do
CONSOLE
done
