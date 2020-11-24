#!/usr/bin/bash

# INETNUM v1.1 2020

# Colors:
color="\e[32m"
normal="\e[0m"

banner() {
	clear
	echo -e $color"    _            __ "                     
	echo -e "   (_)___  ___  / /_____  __  ______ ___ "
	echo -e "  / / __ \/ _ \/ __/ __ \/ / / / __  __ \\"
	echo -e " / / / / /  __/ /_/ / / / /_/ / / / / / /"
	echo -e "/_/_/ /_/\___/\__/_/ /_/\__,_/_/ /_/ /_/ by w315"
	echo -e $normal
}

# Create a list of hosts running common exploitable or interesting services (internal network)
if [ $# -eq 0 ]; then 
	banner
	echo "Usage: ./inetnum.sh targets.txt"
	echo
	echo "Description:"
	echo "This tool enumerates specific common services from a list of targets provided."
	echo
	echo "Supported Services:"
	echo "HTTP,HTTPS,RDP,VNC,FTP,TELNET,SNMP,SMB,TFTP"
	echo
	exit
fi

if [ ! -f $1 ]; then
	banner
	echo "[ERROR] The file you specified does not exist."
	echo
	exit
fi

hosts=$(wc -l < $1)

if [ $hosts == "0" ]; then
	banner
	echo "[ERROR] The file you provided seems empty. Add at least 1 host."
	echo
	exit
fi

# Start
banner
echo "# Found "$hosts" hosts."
echo "- Scanning for TCP services.."
masscan -p 80,88,8080,8081,443,8443,8444,445,21,23,3389,5900,5901 -iL $1 -oX TCP.tmp > /dev/null 2>&1
echo "- Scanning for UDP services.."
masscan -p U:69,U:161 -iL $1 -oX UDP.tmp > /dev/null 2>&1
echo

if [ ! -d "./services" ]; then
	mkdir services
fi
echo "# Extracting common services..."

awk -F'"' '/80/ {print $4":"$10}' TCP.tmp > ./services/HTTP.txt
quanti=$(wc -l < ./services/HTTP.txt)
echo "- Found "$quanti "HTTP Services."

awk -F'"' '/44/ {print $4":"$10}' TCP.tmp > ./services/HTTPS.txt
quanti=$(wc -l < ./services/HTTPS.txt)
echo "- Found "$quanti "HTTPS Services."

awk -F'"' '/21/ {print $4}' TCP.tmp > ./services/FTP.txt
quanti=$(wc -l < ./services/FTP.txt)
echo "- Found "$quanti "FTP Services."

awk -F'"' '/23/ {print $4}' TCP.tmp > ./services/TELNET.txt
quanti=$(wc -l < ./services/TELNET.txt)
echo "- Found "$quanti "TELNET Services."

awk -F'"' '/445/ {print $4}' TCP.tmp > ./services/SMB.txt
quanti=$(wc -l < ./services/SMB.txt)
echo "- Found "$quanti "SMB Services."

awk -F'"' '/445/ {print $4}' TCP.tmp > ./services/RDP.txt
quanti=$(wc -l < ./services/RDP.txt)
echo "- Found "$quanti "RDP Services."

awk -F'"' '/590/ {print $4":"$10}' TCP.tmp > ./services/VNC.txt
quanti=$(wc -l < ./services/VNC.txt)
echo "- Found "$quanti "VNC Services."

awk -F'"' '/69/ {print $4}' UDP.tmp > ./services/TFTP.txt
quanti=$(wc -l < ./services/TFTP.txt)
echo "- Found "$quanti "TFTP Services."

awk -F'"' '/161/ {print $4}' UDP.tmp > ./services/SNMP.txt
quanti=$(wc -l < ./services/SNMP.txt)
echo "- Found "$quanti "SNMP Services."

echo
echo "# Enumerating discovered services..."
if [ ! -d "./services/evidence" ]; then
	mkdir ./services/evidence
fi

# Extracting URLs
echo "- Creating a list of URLs..."
awk -F'"' '/80/ {print "http://"$4":"$10}' TCP.tmp >> ./services/evidence/URLs.txt
awk -F'"' '/443/ {print "https://"$4":"$10}' TCP.tmp >> ./services/evidence/URLs.txt

# Running Eyewitness
which eyewitness > /dev/null 2>&1
if [ "$?" -eq 0 ]; then
	echo "- Running Eyewitness on discovered Web services..."
	eyewitness --no-prompt --web -f ./services/evidence/URLs.txt -d ./services/evidence/Eyewitness > /dev/null 2>&1
fi

# Running SMBMap
which smbmap > /dev/null 2>&1
if [ "$?" -eq 0 ]; then
	echo "- Checking SMB Shares on discovered services..."
	for ip in $(cat ./services/SMB.txt); do
		smbmap -H $ip >> ./services/evidence/SMB-Shares.txt
	done
fi

# Creating list of hosts with SMB Signing disabled
echo "- Creating a list of hosts with SMB Signing disabled..."
nmap -Pn -n -iL ./services/SMB.txt -p445 --script=smb-security-mode -oN .nmap-smb-signing.tmp > /dev/null 2>&1
cat .nmap-smb-signing.tmp | grep disabled -B 15 | grep "for" | cut -d " " -f5 > ./services/evidence/SMB-Signing-Disabled.txt
rm .nmap-smb-signing.tmp

# Running SNMP-Check
which snmp-check > /dev/null 2>&1
if [ "$?" -eq 0 ]; then
	echo "- Checking SNMP services for default community strings..."
	mkdir ./services/evidence/SNMP-Checks
	for ip in $(cat ./services/SNMP.txt); do
		snmp-check $ip > ./services/evidence/SNMP-Checks/$ip-snmp.txt
	done
fi

# Checking FTP (Nmap)
echo "- Checking FTP Services for Anonymous access..."
nmap -Pn -n -iL ./services/FTP.txt -p21 -sC -oN ./services/evidence/FTP-Anon-Access-Check.txt

echo
echo "Removing temporary files..."
rm TCP.tmp
rm UDP.tmp
echo "Finished running all checks. Thanks for using inetnum!"
exit

