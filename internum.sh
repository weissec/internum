#!/usr/bin/bash

# INTERNUMv1.0 2023
# Last edit: 28/11/2023

# Colors:
green="\e[32m"
red="\e[31m"
normal="\e[0m"

banner() {
	clear
	echo -e $green               
	echo -e "    _       __                                "
	echo -e "   (_)___  / /____  _________  __  __________ "
	echo -e "  / / __ \/ __/ _ \/ ___/ __ \/ / / / __  __ \\"
	echo -e " / / / / / /_/  __/ /  / / / / /_/ / / / / / /"
	echo -e "/_/_/ /_/\__/\___/_/  /_/ /_/\__,_/_/ /_/ /_/ by W3155"
	echo -e $normal
}

# COMPATIBILITY CHECKS
banner
echo -e $green"---------------------------------------------------------------------"$normal
echo

starttime=$(date)

if [ $(id -u) != "0" ]; then
	echo -e $red"[ERROR] This script must be run with sudo/root privileges. \n"$normal
	exit
fi

if [ $# -eq 0 ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then 
	banner
	echo -e $green"Usage: ./internum.sh [file]"
	echo
	echo "[file]	Specify the path of a file containing either a list of IP Addresses/Ranges OR a Nessus scan file in .nessus format."
	echo
	echo "Example: ./internum.sh targets.txt"
	echo "Example: ./internum.sh scan.nessus"
	echo
	echo -e "-h,--help  :  Show this helper"$normal
	exit
fi

inputfile=$1

if [ ! -f $inputfile ]; then
	banner
	echo -e $red"[ERROR] The file you specified does not exist."$normal
	exit
fi

if [ ! -s $inputfile ]; then
	banner
	echo -e $red"[ERROR] The file you provided seems empty."$normal
	exit
fi

# Detect if Nessus file or targets list
if grep -q "<?xml" $inputfile; then
	if grep -q "Nessus" $inputfile; then
	    	echo -e $green"# Input file detected as:"$normal" Tenable Nessus file."
	    	inputype="N"
	else
		echo -e $red"[ERROR] Input file not recognised. Please provide a list of targets or a Nessus scan export."$normal
		exit
	fi
else
    	echo -e $green"# Input file detected as:"$normal" IP Addresses/Ranges List"
    	inputype="L"
fi

# Creating project folder
projectname="internum-$(date +%Y%m%d%H%M%S)"

if [ ! -d "./$projectname" ]; then
	mkdir $projectname
else
	echo -e $red"[ERROR] Project folder already exists. Quitting.."$normal
	exit
fi

echo -e $green"# Created project folder:"$normal $projectname

# Function 1: Nessus based input
	
functionone () {
	
	# extracting services
	echo "- Checking Nessus results.."
	# Check how many hosts in scope and set "hosts" variable again
	
	echo "- Extracting Open Services.."
	
	echo "The functionality is still under development. Please use a txt list of targets instead."
	exit
	# TBC
}

# Function 2: List based input

functiontwo () {
		
	# Start (scanning targets for common ports)
	echo -e $green"# Extracting targets from file:"$normal $inputfile
	# Using Nmap to resolve and order IP ranges
	nmap -sL -n -iL $inputfile | grep -i "scan report for" | cut -d " " -f5 > ./$projectname/targets.txt
	echo -e $green"# Number of Hosts Found:"$normal $(wc -l < ./$projectname/targets.txt)
	echo
	
	servicescan () {
		echo -e $green"# Please select which scan type you would wish to run:"$normal
		echo " - [1] Standard (more accurate but slower)"
		echo " - [2] Fast (faster but less accurate)"
		echo
		read -p "Please select scan type by entering 1 or 2: " scantype
		
		# Remember to add here new services checks
		
		if [[ "$scantype" == 1 ]]; then
		
			which nmap > /dev/null 2>&1
			if [ "$?" != 0 ]; then
				echo -e $red "[ERROR] Nmap does not seem to be installed but it is required for this scan type."$normal
				servicescan
			fi	
		
			echo -e $green"\n# scanning for TCP services.. (Standard Scan)"$normal
			nmap -p 22,80,88,8080,8081,443,8443,445,21,23,3389,5900,5901,2049,79,25,389,636 --open -iL $inputfile -oG ./$projectname/.TCP.tmp > /dev/null 2>&1
			echo -e $green"# Scanning for UDP services.. (Standard Scan)"$normal
			nmap -sU -p 69,161 -iL $inputfile -oG ./$projectname/.UDP.tmp > /dev/null 2>&1
		elif [[ "$scantype" == 2 ]]; then
		
			which masscan > /dev/null 2>&1
			if [ "$?" != 0 ]; then
				echo -e $red "[ERROR] Masscan does not seem to be installed but it is required for this scan type."$normal
				servicescan
			fi
			echo -e $green"\n# Scanning for TCP services.. (Fast Scan)"$normal
			masscan -p 22,80,88,8080,8081,443,8443,445,21,23,3389,5900,5901,2049,79,25,389,636 -iL $inputfile -oX ./$projectname/.TCP.tmp > /dev/null 2>&1
			echo -e $green"# Scanning for UDP services.. (Fast Scan)"$normal
			masscan -p U:69,U:161 -iL $inputfile -oX ./$projectname/.UDP.tmp > /dev/null 2>&1
		else
			echo
			echo -e $red"[ERROR] Invalid option. Please enter one of the available options: 1 or 2"$normal
			servicescan
		fi
	}
	
	# Running scans
	servicescan
	
	# Check if scans worked 
	if [ $(wc -l < ./$projectname/.TCP.tmp) == "0" ]; then
	
		if [ $(wc -l < ./$projectname/.UDP.tmp) == "0" ]; then
			banner
			echo -e $green"\n# No services found. Either the provided targets are incorrect or you can't reach them."
			echo -e "# Quitting.."$normal
			exit
		fi
	fi

	echo -e $green"# All Scans completed."$normal

	# Ensure that scans results format look the same for both scans types (Nmap/Masscan)
	# Format: IP:port
	# Format Nmap/Masscan results and combine TCP/UDP files:
	if [[ "$scantype" == 1 ]]; then
		awk -F'[/ ]' '{h=$2; for(i=1;i<=NF;i++){if($i=="open"){print h":"$(i-1)}}}' ./$projectname/.TCP.tmp >> ./$projectname/TCP.txt
		awk -F'[/ ]' '{h=$2; for(i=1;i<=NF;i++){if($i=="open"){print h":"$(i-1)}}}' ./$projectname/.UDP.tmp >> ./$projectname/UDP.txt
	elif [[ "$scantype" == 2 ]]; then
		awk -F'"' '/open/ {print $4":"$10}' ./$projectname/.TCP.tmp >> ./$projectname/TCP.txt
		awk -F'"' '/open/ {print $4":"$10}' ./$projectname/.UDP.tmp >> ./$projectname/UDP.txt
	else
		echo -e $red"[ERROR] Error extracting services from scan results."$normal
	fi

	# Check if any results, if not quit
	
	if [ -s "./$projectname/TCP.txt" ] || [ -s "./$projectname/TCP.txt" ]; then
	
		# Removing temporary files
		rm ./$projectname/.TCP.tmp > /dev/null 2>&1
		rm ./$projectname/.UDP.tmp > /dev/null 2>&1
		
		# Create Evidence folder
		if [ ! -d "./$projectname/evidence" ]; then
			mkdir ./$projectname/evidence
		fi
		if [ ! -d "./$projectname/services" ]; then
			mkdir ./$projectname/services
		fi
		
		# Sort and unique services
		sort -u -o ./$projectname/TCP.txt ./$projectname/TCP.txt
		sort -u -o ./$projectname/UDP.txt ./$projectname/UDP.txt
	
	else
		echo -e $green"\nNo open services found."$normal
		exit	
	fi

	# List number of services found:
	echo -e $green"\n# Number of services found (TCP/UDP):"$normal

	check_service() {
		port=$1
		file_suffix=$2
		pprotocol=$3
	  	servcount=$(grep ":$port" ./$projectname/$3.txt | wc -l)
		if (($servcount > 0)); then
			echo "- $file_suffix: $servcount"
			grep -E ":$port" ./$projectname/$3.txt >> ./$projectname/services/$file_suffix.txt
		fi
	}

	check_service 22 SSH TCP
	check_service 80 HTTP TCP
	check_service "*443" HTTPS TCP
	check_service 445 SMB TCP
	check_service 21 FTP TCP
	check_service 590 VNC TCP
	check_service 69 TFTP UDP
	check_service 23 TELNET TCP
	check_service 161 SNMP UDP
 	check_service 111 NFS TCP
	check_service 2049 NFS TCP
	check_service 3389 RDP TCP
	check_service 79 FINGER TCP
	check_service 25 SMTP TCP
	check_service 389 LDAP TCP
	check_service 636 LDAPS TCP
	check_service "88($|\s)" KERBEROS TCP
	# add more here

} # end list based function

# Call script function based on input type (Nessus or IP list)

if [ $inputype == "N" ]; then

	# Run function 1
	functionone
	
elif [ $inputype == "L" ]; then

	# Run function 2
	functiontwo
	
else
	echo -e $red"[ERROR] Invalid input file. Quitting.."$normal
	exit
fi

# Export list of services in CSV format

	# IP Address, Port, Protocol, Service Type
	# TO BE ADDED

# Moving to enumeration of specific services
# Skip service check if no ports found
echo
echo -e $green"# Enumerating discovered services..."$normal

# HTTP and HTTPS

if [ -f "./$projectname/services/HTTP.txt" ]; then
	echo "> Checking: HTTP"
    	awk -F':' '/:80/ {print "http://"$1":"$2}' ./$projectname/services/HTTP.txt >> ./$projectname/evidence/URLs.txt
    	# Add vuln
	echo "- [CONFIRMED] Cleartext protocols in use." >> ./$projectname/evidence/vulnerabilities.txt
fi 
if [ -f "./$projectname/services/HTTPS.txt" ]; then
	echo "> Checking: HTTPS"
	awk -F':' '/:*443/ {print "https://"$1":"$2}' ./$projectname/services/HTTPS.txt >> ./$projectname/evidence/URLs.txt
fi
if [ -f "./$projectname/evidence/URLs.txt" ]; then

	# Running Eyewitness
	which eyewitness > /dev/null 2>&1
	if [ "$?" != 0 ]; then
		echo "- Skipping HTTP/S services screenshots as Eyewitness was not found."
	else
		echo "- Running Eyewitness on HTTP/S services..."
		eyewitness --no-prompt --web -f ./$projectname/evidence/URLs.txt -d ./$projectname/evidence/eyewitness > /dev/null 2>&1
		# Add vuln
		echo "- [POTENTIAL] Check Eyewitness results for any unauthenticated services or default credentials." >> ./$projectname/evidence/vulnerabilities.txt
	fi
fi

# SSH
# Checking for brute-force
# Checking for Weak Ciphers and Key Exchange Algorithms
if [ -f "./$projectname/services/SSH.txt" ]; then

	echo "> Checking: SSH"
	mkdir ./$projectname/evidence/SSH-Checks
	cat ./$projectname/services/SSH.txt | cut -d ":" -f1 >> ./$projectname/evidence/.ssh-targets.tmp
	for ipp in $(cat ./$projectname/evidence/.ssh-targets.tmp); do
		nmap -p 22 -sV --script ssh-auth-methods --script ssh2-enum-algos $ipp -oN ./$projectname/evidence/SSH-Checks/$ipp-SSH-Config.txt
		# Add vuln
		echo "- [POTENTIAL] SSH Password Authentication, vulnerable to brute-force." >> ./$projectname/evidence/vulnerabilities.txt
		echo "- [POTENTIAL] Weak SSH Ciphers and Key-Exchange Algorithms." >> ./$projectname/evidence/vulnerabilities.txt
	done
	rm ./$projectname/evidence/.ssh-targets.tmp
fi

# SMB
# Running SMBMap
if [ -f "./$projectname/services/SMB.txt" ]; then
	echo "> Checking: SMB"
	echo "- Enumerating SMB services and shares.."
	# removing port number from targets
	cat ./$projectname/services/SMB.txt | cut -d ":" -f1 >> ./$projectname/evidence/.smb-targets.tmp
	# running checks
	nmap --script "safe or smb-enum-*" -p 445 -iL ./$projectname/evidence/.smb-targets.tmp -oN ./$projectname/evidence/SMB-Enumeration.txt > /dev/null 2>&1
	# Add vuln
	echo "- [POTENTIAL] Check if any obsolete SMBv1 services are present." >> ./$projectname/evidence/vulnerabilities.txt
	
	# Creating list of hosts with SMB Signing disabled
	echo "- Creating a list of hosts with SMB Signing disabled..."
	nmap -Pn -n -iL ./$projectname/services/SMB.txt  -p445 --script=smb-security-mode -oN ./$projectname/evidence/.smb-signing.tmp > /dev/null 2>&1
	cat ./$projectname/evidence/.smb-signing.tmp | grep disabled -B 15 | grep "for" | cut -d " " -f5 > ./$projectname/evidence/SMB-Signing-Disabled.txt
	rm ./$projectname/evidence/.smb-signing.tmp
	rm ./$projectname/evidence/.smb-targets.tmp
	# Add vuln
	echo "- [CONFIRMED] Hosts with SMB Signing disabled or not required." >> ./$projectname/evidence/vulnerabilities.txt
	echo "- [POTENTIAL] Check accessible SMB shares for sensitive content." >> ./$projectname/evidence/vulnerabilities.txt
fi

# SNMP
# Running SNMP-Check
if [ -f "./$projectname/services/SNMP.txt" ]; then
	which snmp-check > /dev/null 2>&1
	if [ "$?" != 0 ]; then
		echo "- SNMP-Check does not seem to be installed. Skipping step."
	else
		echo "> Checking: SNMP"
		mkdir ./$projectname/evidence/SNMP-Checks
		cat ./$projectname/services/SNMP.txt | cut -d ":" -f1 >> ./$projectname/evidence/.snmp-targets.tmp
		for ipp in $(cat ./$projectname/evidence/.snmp-targets.tmp); do
			snmp-check $ipp > ./$projectname/evidence/SNMP-Checks/$ipp-snmp.txt
			# Add vuln
			echo "- [CONFIRMED] Cleartext protocols in use." >> ./$projectname/evidence/vulnerabilities.txt
			echo "- [POTENTIAL] Check default community strings on SNMP services." >> ./$projectname/evidence/vulnerabilities.txt
		done
		rm ./$projectname/evidence/.snmp-targets.tmp
	fi
fi

# FTP
# Checking FTP (Nmap)
if [ -f "./$projectname/services/FTP.txt" ]; then
	echo "> Checking: FTP"
	# removing port number from targets
	cat ./$projectname/services/FTP.txt | cut -d ":" -f1 >> ./$projectname/evidence/.ftp-targets.tmp
	# running checks
	nmap -Pn -n -iL ./$projectname/evidence/.ftp-targets.tmp -p21 -sC -oN ./$projectname/evidence/FTP-Checks.txt > /dev/null 2>&1
	rm ./$projectname/evidence/.ftp-targets.tmp
	# Add vuln
	echo "- [POTENTIAL] Check for anonymous access on FTP services." >> ./$projectname/evidence/vulnerabilities.txt
	echo "- [CONFIRMED] Cleartext protocols in use." >> ./$projectname/evidence/vulnerabilities.txt
fi
# TELNET
if [ -f "./$projectname/services/TELNET.txt" ]; then
	echo "> Checking: TELNET"
	# removing port number from targets
	cat ./$projectname/services/TELNET.txt | cut -d ":" -f1 >> ./$projectname/evidence/.telnet-targets.tmp
	# running checks
	nmap -sV -Pn --script "*telnet*" -p 23 -iL ./$projectname/evidence/.telnet-targets.tmp -oN ./$projectname/evidence/TELNET-Checks.txt > /dev/null 2>&1
	# Add vuln
	echo "- [CONFIRMED] Cleartext protocols in use." >> ./$projectname/evidence/vulnerabilities.txt
	rm ./$projectname/evidence/.telnet-targets.tmp
fi
# TFTP
if [ -f "./$projectname/services/TFTP.txt" ]; then
	echo "> Checking: TFTP"
	# removing port number from targets
	cat ./$projectname/services/TFTP.txt | cut -d ":" -f1 >> ./$projectname/evidence/.tftp-targets.tmp
	# running checks
	nmap -Pn -sU -p69 -sV --script tftp-enum -iL ./$projectname/evidence/.tftp-targets.tmp -oN ./$projectname/evidence/TFTP-Checks.txt > /dev/null 2>&1
	rm ./$projectname/evidence/.tftp-targets.tmp
fi
# RDP
if [ -f "./$projectname/services/RDP.txt" ]; then
	echo "> Checking: RDP"
	# removing port number from targets
	cat ./$projectname/services/RDP.txt | cut -d ":" -f1 >> ./$projectname/evidence/.rdp-targets.tmp
	# running checks
	nmap -sV -Pn --script "rdp*" -p 3389 -iL ./$projectname/evidence/.rdp-targets.tmp -oN ./$projectname/evidence/RDP-Checks.txt > /dev/null 2>&1
	rm ./$projectname/evidence/.rdp-targets.tmp
	# Add vuln
	echo "- [POTENTIAL] Check if NLA is implemented for RDP services." >> ./$projectname/evidence/vulnerabilities.txt
fi
# VNC
if [ -f "./$projectname/services/VNC.txt" ]; then
	echo "> Checking: VNC"
	# removing port number from targets
	cat ./$projectname/services/VNC.txt | cut -d ":" -f1 >> ./$projectname/evidence/.vnc-targets.tmp
	# running checks
	nmap -Pn -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p 5900,5901 -iL ./$projectname/evidence/.vnc-targets.tmp -oN ./$projectname/evidence/VNC-Checks.txt > /dev/null 2>&1
	rm ./$projectname/evidence/.vnc-targets.tmp
	# Add vuln
	echo "- [POTENTIAL] Check for any unauthenticated VNC services." >> ./$projectname/evidence/vulnerabilities.txt
fi
# FINGER
if [ -f "./$projectname/services/FINGER.txt" ]; then
	echo "> Checking: FINGER"
	# removing port number from targets
	cat ./$projectname/services/FINGER.txt | cut -d ":" -f1 >> ./$projectname/evidence/.finger-targets.tmp
	# running checks
	nmap -Pn -sV -sC -p 79 -iL ./$projectname/evidence/.finger-targets.tmp -oN ./$projectname/evidence/FINGER-Checks.txt > /dev/null 2>&1
	rm ./$projectname/evidence/.finger-targets.tmp
fi
# NFS
if [ -f "./$projectname/services/NFS.txt" ]; then
	echo "> Checking: NFS"
	# removing port number from targets
	cat ./$projectname/services/NFS.txt | cut -d ":" -f1 >> ./$projectname/evidence/.nfs-targets.tmp
	# running checks
	nmap -Pn --script=nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse -p 2049 -iL ./$projectname/evidence/.nfs-targets.tmp -oN ./$projectname/evidence/NFS-Checks.txt > /dev/null 2>&1
	rm ./$projectname/evidence/.nfs-targets.tmp
	# Add vuln
	echo "- [POTENTIAL] Check content of any NFS shares for sensitive data." >> ./$projectname/evidence/vulnerabilities.txt
fi
# SMTP
if [ -f "./$projectname/services/SMTP.txt" ]; then
	echo "> Checking: SMTP"
	# removing port number from targets
	cat ./$projectname/services/SMTP.txt | cut -d ":" -f1 >> ./$projectname/evidence/.smtp-targets.tmp
	# running checks
	nmap -Pn --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 -iL ./$projectname/evidence/.smtp-targets.tmp -oN ./$projectname/evidence/SMTP-Checks.txt > /dev/null 2>&1
	# Add vuln
	echo "- [CONFIRMED] Cleartext protocols in use." >> ./$projectname/evidence/vulnerabilities.txt
	rm ./$projectname/evidence/.smtp-targets.tmp
fi
# LDAP
if [ -f "./$projectname/services/LDAP.txt" ]; then
	echo "> Checking: LDAP"
	# removing port number from targets
	cat ./$projectname/services/LDAP.txt | cut -d ":" -f1 >> ./$projectname/evidence/.ldap-targets.tmp
	# running checks
	nmap -Pn -n -p 389 --script "ldap* and not brute" -iL ./$projectname/evidence/.ldap-targets.tmp -oN ./$projectname/evidence/LDAP-Checks.txt > /dev/null 2>&1
	rm ./$projectname/evidence/.ldap-targets.tmp
fi
# LDAPS
if [ -f "./$projectname/services/LDAPS.txt" ]; then
	echo "> Checking: LDAPS"
	# removing port number from targets
	cat ./$projectname/services/LDAPS.txt | cut -d ":" -f1 >> ./$projectname/evidence/.ldaps-targets.tmp
	# running checks
	nmap -Pn -n -p 636 --script "ldap* and not brute" -iL ./$projectname/evidence/.ldaps-targets.tmp -oN ./$projectname/evidence/LDAPS-Checks.txt > /dev/null 2>&1
	rm ./$projectname/evidence/.ldaps-targets.tmp
fi
# AD Checks
if [ -f "./$projectname/services/LDAP.txt" ] || [ -f "./$projectname/services/LDAPS.txt" ] || [ -f "./$projectname/services/KERBEROS.txt" ]; then
	# Check for Domain Controllers
	# if port 88,636,389 open
	if [ -f "./$projectname/services/LDAP.txt" ]; then
		cat ./$projectname/services/LDAP.txt | cut -d ":" -f1 >> ./$projectname/evidence/.dcs.tmp
	fi
	if [ -f "./$projectname/services/LDAPS.txt" ]; then
		cat ./$projectname/services/LDAPS.txt | cut -d ":" -f1 >> ./$projectname/evidence/.dcs.tmp
	fi
	if [ -f "./$projectname/services/KERBEROS.txt" ]; then
		cat ./$projectname/services/KERBEROS.txt | cut -d ":" -f1 >> ./$projectname/evidence/.dcs.tmp
	fi
	
	sort -u -o ./$projectname/evidence/.dcs.tmp ./$projectname/evidence/.dcs.tmp
	
	for hostline in $(cat "./$projectname/evidence/.dcs.tmp"); do
	
		hostnamevar=$(nmblookup -A $hostline | awk '/ACTIVE/ {print $1; exit}')
		domainvar=$(nmblookup -A $hostline | awk '/GROUP/ {print $1; exit}')
		echo "DC IP: "$hostline" - Hostname: "$hostnamevar" - Domain NetBios Name: "$domainvar >> ./$projectname/evidence/AD-Information.txt
	done
	
	rm ./$projectname/evidence/.dcs.tmp
	echo "> AD Domain environment detected. Details:"
	cat ./$projectname/evidence/AD-Information.txt
	
	# Add vuln
	echo "- [POTENTIAL] Check for null-session on Domain Controllers." >> ./$projectname/evidence/vulnerabilities.txt
fi

if [ -f "./$projectname/evidence/vulnerabilities.txt" ]; then
	# Show Vulnerabilities:
	echo -e $green"\nIssues discovered:"$normal
	# Remove duplicates
	sort -u -o ./$projectname/evidence/vulnerabilities.txt ./$projectname/evidence/vulnerabilities.txt
	cat ./$projectname/evidence/vulnerabilities.txt
fi

# HTML Report?

rm ./$projectname/UDP.txt
rm ./$projectname/TCP.txt

# End
echo
echo -e $green"[DONE] Please find all results in the project folder."
echo -e "---------------------------------------------------------------------"
echo -e "Test started: "$starttime
echo -e "Test finished: "$(date) 
echo -e $normal
exit
