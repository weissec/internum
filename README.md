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
HTTP, HTTPS, RDP, VNC, FTP, TFTP, TELNET, SNMP, SMB, NFS, FINGER

### Disclaimer: 
Service discovery is based only on IANA Service Name and Transport Protocol Port Number Registry.
For this reason, services running on custom ports will not be tested.

### Requirements: 
Root privileges
Pre-installed packages
