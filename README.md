# iNETNUM
Bash wrapper for basic local services enumeration for internal networks penetration tests.

### Usage: 
`chmod +x inetnum.sh`    
`./inetnum.sh targets.txt`  

### Description:
This tool enumerates specific common services from a list of targets provided.
This script is written in BASH and it's designed as a one-file script for portability.

### Supported Services:
HTTP, HTTPS, RDP, VNC, FTP, TELNET, SNMP, SMB, TFTP

### Disclaimer: 
Service discovery is based only on IANA Service Name and Transport Protocol Port Number Registry.
For this reason, services running on custom ports will not be tested.


### ISSUES: 
Scripts only run as root (otherwise need to add sudo to each command)
