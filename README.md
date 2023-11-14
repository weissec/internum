# iNETNUM
Bash wrapper for basic local services enumeration for internal networks.

### Usage: 
`chmod +x inetnum.sh`    
`./inetnum.sh targets.txt`  

### Description:
This tool enumerates specific common services from a list of target IPs/subnets provided.
This script is written in BASH and it's designed as a one-file script for portability.
For this reason, the functionality is dependant on specific packages being installed on the system.

### Supported Services:
HTTP, HTTPS, RDP, VNC, FTP, TFTP, TELNET, SNMP, SMB, NFS, FINGER, SMTP

### Disclaimer: 
Service discovery is based only on IANA Service Name and Transport Protocol Port Number Registry.
For this reason, services running on custom ports will not be tested.

### Requirements: 
Sudo privileges,
Pre-installed packages (Nmap, Masscan, Eyewitness, SMBMap, SNMP-Check)

### Changes / TODO:
- Potentially change name to Internum.
- Sort IP addresses / targets numerically or alphabetically (if hostnames)
- Add checks for NFS shares (port 2049/tcp)
- Add more checks for other interesting services.
- Add compatibility checks for running script (root privileges, dependancies installed, etc)
- Check Eyewitness is still working and add workaround such as Gowitness when not available.
- Add a timeout on Nmap scripts for specific checks in case it hangs due to errors.
- Add checks for LDAP (389/tcp). For example: nmap -Pn -n -p 389 --script "ldap* and not brute" <IP>
- Add support for other SMB ports (137, 139 TCP)
- Slow down the scans, currently reporting lots of False Positive results for open ports.
- Before counting the hosts for each service type, do a "sort -u" to remove duplicates.
- Replace Masscan with Nmap for better results. Masscan does not accept Hostnames as targets and reports false positives.
- Add a new function for automatic Active Directory Domain checks: Domain Name, list of DCs, Null sessions, etc.
- Add HTML report functionality (potentially with graphs and other stats).
