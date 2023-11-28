# Internum
Bash wrapper for basic local services enumeration on internal (local) networks.

### Usage: 
`chmod +x inetnum.sh`    
`./internum.sh targets.txt` 
`./internum.sh -h` 

### Description:
This tool enumerates specific common services from a list of target IPs/subnets provided or a Nessus file.
This script is written in BASH and it's designed as a one-file script for portability.
For this reason, the functionality is dependant on specific packages being installed on the system.

### Supported Services:
HTTP, HTTPS, RDP, VNC, FTP, TFTP, TELNET, SNMP, SMB, NFS, FINGER, SMTP, LDAP, LDAPS, KERBEROS,

### Disclaimer: 
Service discovery is based only on IANA Service Name and Transport Protocol Port Number Registry.
For this reason, services running on custom ports will not be tested.

### Requirements: 
- Sudo privileges
- Pre-installed packages (Nmap, Masscan, Eyewitness, SMBMap, SNMP-Check)

### Changes / TODO:
- Add more checks for other interesting services.
- Add a timeout on Nmap scripts for specific checks in case it hangs due to errors.
- Add HTML report functionality (potentially with graphs and other stats).
- Add CSV report functionality.
