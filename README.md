# Internum
Bash wrapper for basic local services enumeration on internal (local) networks.

### Usage: 
```
git clone https://github.com/weissec/internum.git`
chmod +x internum.sh    
sudo internum.sh -h
```

### Description:
This tool enumerates specific common services from a list of target IPs/ranges provided or a Nessus file (.nessus).
This script is written in BASH and it's designed as a one-file script for portability.
For this reason, the functionality is dependant on specific packages being installed on the system (see requirements section below).

### Current Supported Services:
SSH, HTTP, HTTPS, RDP, VNC, FTP, TFTP, TELNET, SNMP, SMB, NFS, FINGER, SMTP, LDAP, LDAPS, KERBEROS

### Disclaimer: 
Service discovery is based only on IANA Service Name and Transport Protocol Port Number Registry.
For this reason, services running on custom ports will likely be not tested.

### Requirements: 
- Sudo/root privileges
- Pre-installed packages: Nmap, Masscan, Eyewitness, SMBMap, SNMP-Check

### Output:
- TXT file containing a list of potential vulnerabilities
- Log file with timestamps of activities
- HTML report with list of services and findings.
