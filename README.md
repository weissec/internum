# Internum
Bash wrapper for basic local services enumeration on internal (local) networks.

### Usage: 
```
git clone https://github.com/weissec/internum.git
sudo chmod +x internum.sh    
sudo internum.sh -h
```

### Description:
This tool enumerates specific common network services from a list of target IPs/ranges provided.
This script is written in BASH and it's designed as a one-file script for portability.
For this reason, the functionality is dependant on specific packages being installed on the system (see requirements section below).

### Current Supported Services:
SSH, HTTP, HTTPS, RDP, VNC, FTP, TFTP, TELNET, SNMP, SMB, NFS, Finger, SMTP, LDAP, LDAPS, Kerberos, DNS, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Docker, Kubernetes, SIP, RTSP, RPC,  Oracle

### Disclaimer: 
Service discovery is based only on IANA Service Name and Transport Protocol Port Number Registry.
For this reason, services running on custom ports will likely be ignored.

### Requirements: 
- Sudo/root privileges
- Pre-installed packages (minimum required: Nmap)

### Output:
- TXT file containing a list of potential vulnerabilities
- Log file with timestamps of activities
- HTML report with list of live hosts, services and potential vulnerabilities.
