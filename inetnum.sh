#!/usr/bin/bash

# INETNUM v1.2 2022

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

# Performing basic checks

if [ $(id -u) != "0" ]; then
	echo -e "[ERROR] This script must be run with sudo/root privileges. \n"
	exit
fi

which masscan > /dev/null 2>&1
if [ "$?" != 0 ]; then
	echo "[ERROR] Masscan does not seem to be installed and it is required for this script."
	exit
fi

which nmap > /dev/null 2>&1
if [ "$?" != 0 ]; then
	echo "[ERROR] Nmap does not seem to be installed and it is required for this script."
	exit
fi

if [ $# -eq 0 ]; then 
	banner
	echo "Usage: ./inetnum.sh targets.txt"
	echo
	echo "Description:"
	echo "This tool enumerates specific common internal services from a list of targets (IPs/Ranges) provided."
	echo
	echo "Supported Services:"
	echo "HTTP, HTTPS, RDP, VNC, FTP, TFTP, TELNET, SNMP, SMB, NFS, FINGER, SMTP"
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

# Start (scanning targets for common ports)
banner
echo "# Found "$hosts" entries."
echo "- Scanning for TCP services.."
masscan -p 80,88,8080,8081,443,8443,445,21,23,3389,5900,5901,2049,79,25 -iL $1 -oX TCP.tmp > /dev/null 2>&1
echo "- Scanning for UDP services.."
masscan -p U:69,U:161 -iL $1 -oX UDP.tmp > /dev/null 2>&1
echo

if [ ! -d "./services" ]; then
	mkdir services
fi

# Saving results
echo "# Extracting common services..."

awk -F'"' '/80/ {print $4":"$10}' TCP.tmp > ./services/HTTP.txt
quanti=$(wc -l < ./services/HTTP.txt)
echo "- Found "$quanti "HTTP Services."

awk -F'"' '/443/ {print $4":"$10}' TCP.tmp > ./services/HTTPS.txt
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

awk -F'"' '/590/ {print $4}' TCP.tmp > ./services/VNC.txt
quanti=$(wc -l < ./services/VNC.txt)
echo "- Found "$quanti "VNC Services."

awk -F'"' '/69/ {print $4}' UDP.tmp > ./services/TFTP.txt
quanti=$(wc -l < ./services/TFTP.txt)
echo "- Found "$quanti "TFTP Services."

awk -F'"' '/161/ {print $4}' UDP.tmp > ./services/SNMP.txt
quanti=$(wc -l < ./services/SNMP.txt)
echo "- Found "$quanti "SNMP Services."

awk -F'"' '/2049/ {print $4}' TCP.tmp > ./services/NFS.txt
quanti=$(wc -l < ./services/NFS.txt)
echo "- Found "$quanti "NFS Services."

awk -F'"' '/3389/ {print $4}' TCP.tmp > ./services/RDP.txt
quanti=$(wc -l < ./services/RDP.txt)
echo "- Found "$quanti "RDP Services."

awk -F'"' '/79/ {print $4}' TCP.tmp > ./services/FINGER.txt
quanti=$(wc -l < ./services/FINGER.txt)
echo "- Found "$quanti "FINGER Services."

# for SMTP, we are currently only listing unencrypted services
awk -F'"' '/25/ {print $4}' TCP.tmp > ./services/SMTP.txt
quanti=$(wc -l < ./services/SMTP.txt)
echo "- Found "$quanti "SMTP Services."

# Moving to enumeration of specific services
echo
echo "# Enumerating discovered services..."
if [ ! -d "./services/evidence" ]; then
	mkdir ./services/evidence
fi

# ------- HTTP and HTTPS
# Extracting URLs
echo "- Creating a list of URLs..."
awk -F'"' '/80/ {print "http://"$4":"$10}' TCP.tmp >> ./services/evidence/URLs.txt
awk -F'"' '/443/ {print "https://"$4":"$10}' TCP.tmp >> ./services/evidence/URLs.txt

# Running Eyewitness
which eyewitness > /dev/null 2>&1
if [ "$?" != 0 ]; then
	echo "[ERROR] Eyewitness does not seem to be installed - no HTTP screenshots will be taken."
else
	echo "- Running Eyewitness on discovered Web services..."
	eyewitness --no-prompt --web -f ./services/evidence/URLs.txt -d ./services/evidence/Eyewitness > /dev/null 2>&1
fi

# ------- SMB
# Running SMBMap
which smbmap > /dev/null 2>&1
if [ "$?" != 0 ]; then
	echo "[ERROR] SMBMap does not seem to be installed - skipping step."
else
	echo "- Checking SMB Shares on discovered services..."
	for ip in $(cat ./services/SMB.txt); do
		smbmap -H $ip >> ./services/evidence/SMB-Shares.txt
		# smbclient --no-pass -L //<IP> # Null user
	done
fi

# Creating list of hosts with SMB Signing disabled

echo "- Creating a list of hosts with SMB Signing disabled..."
nmap -Pn -n -iL ./services/SMB.txt -p445 --script=smb-security-mode -oN .nmap-smb-signing.tmp > /dev/null 2>&1
cat .nmap-smb-signing.tmp | grep disabled -B 15 | grep "for" | cut -d " " -f5 > ./services/evidence/SMB-Signing-Disabled.txt
rm .nmap-smb-signing.tmp

# ------- SNMP
# Running SNMP-Check
which snmp-check > /dev/null 2>&1
if [ "$?" != 0 ]; then
	echo "[ERROR] SNMP-Check does not seem to be installed - skipping step."
else
	echo "- Checking SNMP services for default community strings..."
	mkdir ./services/evidence/SNMP-Checks
	for ip in $(cat ./services/SNMP.txt); do
		snmp-check $ip > ./services/evidence/SNMP-Checks/$ip-snmp.txt
	done
fi

# ------- FTP
# Checking FTP (Nmap)
echo "- Checking FTP Services..."
nmap -Pn -n -iL ./services/FTP.txt -p21 -sC -oN ./services/evidence/FTP-Checks.txt > /dev/null 2>&1

# ------- TELNET
echo "- Checking TELNET Services..."
nmap -sV -Pn --script "*telnet*" -p 23 -iL ./services/TELNET.txt -oN ./services/evidence/TELNET-Checks.txt > /dev/null 2>&1

# ------- TFTP
echo "- Checking TFTP Services..."
nmap -Pn -sU -p69 -sV --script tftp-enum -iL ./services/TFTP.txt -oN ./services/evidence/TFTP-Checks.txt > /dev/null 2>&1

# ------- RDP
echo "- Checking RDP Services.."
nmap -sV -Pn --script "rdp*" -p 3389 -iL ./services/RDP.txt -oN ./services/evidence/RDP-Checks.txt > /dev/null 2>&1

# ------- VNC
echo "- Checking VNC Services..."
nmap -Pn -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p 5900,5901 -iL ./services/VNC.txt -oN ./services/evidence/VNC-Checks.txt > /dev/null 2>&1

# ------- FINGER
echo "- Checking FINGER Services..."
nmap -Pn -sV -sC -p 79 -iL ./services/FINGER.txt -oN ./services/evidence/FINGER-Checks.txt > /dev/null 2>&1

# ------- NFS
echo "- Checking NFS Services..."
nmap -Pn --script=nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse -p 2049 -iL ./services/NFS.txt -oN ./services/evidence/NFS-Checks.txt > /dev/null 2>&1

# ------- SMTP
echo "- Checking SMTP Services..."
nmap -Pn --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 -iL ./services/SMTP.txt -oN ./services/evidence/SMTP-Checks.txt > /dev/null 2>&1


# Cleaning the results
echo
echo "Removing temporary files..."
rm TCP.tmp > /dev/null 2>&1
rm UDP.tmp > /dev/null 2>&1
echo "[DONE] Please find all resuls in the service folder."
exit
