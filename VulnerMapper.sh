#!/bin/bash

### OBJECTIVES: VULNERMAPPER

# automatically install relevant applications
# user enters network range, creates new directory
# SCAN: use nmap and masscan to scan for ports and services, saving information into directory
# NSE: based on scan results, use nmap scripting engine to extract more information
# SEARCHSPLOIT: based on service detection results, use searchsploit to find potential vulnerabilities
# BRUTE FORCE: based on the scanning results, use hydra and medusa to find weak passwords used in the network's login services
# LOG: at the end of the mapping, show the user the scanning statistics: SCAN, NSE, SEARCHSPLOIT, BRUTEFORCE
 
### INSTALLATION FUNCTION

# let the user know that VulnerMapper is starting
echo " "
echo "VulnerMapper is starting..."
echo " "


# define install function
function install()
{
	# let the user know applications are being installed 
	echo " "
	echo "Installing applications on your local computer..."
	echo " "
	
	# update and install latest APT packages
	sudo apt-get update
	sudo apt-get upgrade
	sudo apt-get dist-upgrade
	
  # install figlet for aesthetic purposes
	# create a directory for downloading figlet font
	# install cybermedium figlet font; credits: http://www.figlet.org
	mkdir figrc
	cd ~/SOChecker/figrc
	sudo apt-get install figlet
	wget http://www.jave.de/figlet/fonts/details/cybermedium.flf
	
	# install relevant applications
	sudo apt-get install nmap
	sudo apt-get install masscan
	sudo apt-get install hydra
	
	# let the user know applications are installed
	echo " "
	echo "Applications installed and updated."
	echo "	"
}

# call the install function
install

### NETWORK LOGGING FUNCTION

	# navigate to home directory 
	# create a directory to contain the logs later
	cd ~
	mkdir SOChecker
	cd ~/SOChecker
	
	# create a log file
	touch netlog.log
	
function netlog()
{ 
	# NMAP LOGGING
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
	
	# MASSCAN LOGGING
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
	
	# HYDRA LOGGING
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

### NETWORK ATTACK FUNCTION LOOP

# OPTIONS MENU
function netatk()
{
	# read options for remote control
	read -p "Select an option (A/B/C/D/E):
	
	A) Nmap Port Scan
	B) Masscan Port Scan
	C) MSF SMB Brute-Force Attack
	D) Hydra SMB Brute-Force Attack
	E) Exit
		
	" options
}

# WHILE-TRUE LOOP
# return user to the menu after an option until exit
# credits: CFC/ThinkCyber coursebook, Linux Fundamentals, p49
while true 
do
# display figlet for aesthetics
figlet -c -f ~/SOChecker/figrc/cybermedium.flf -t "SOCHECKER"
# call netatk function
netatk

# OPTION EXECUTION
case $options in


# A. NMAP PORT SCAN 
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

done
