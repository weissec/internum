#!/usr/bin/bash

# INTERNUMv1.2 2023
# Improvements: Hidden scan output, timeout, help facility

# --------------------------
# Configuration Section
# --------------------------
# Colors and formatting
green="\e[32m"
red="\e[31m"
yellow="\e[33m"
blue="\e[34m"
bold="\e[1m"
normal="\e[0m"

# Timeout for scans (in seconds)
SCAN_TIMEOUT=600  # 10 minutes

# Project structure
project_base="internum-$(date +%Y%m%d%H%M%S)"

# Log file
log_file="$project_base/internum.log"

# Port configurations (easily modifiable)
declare -A PORTS=(
    [TCP]="22,80,88,8080,8081,443,8443,445,21,23,3389,5900,5901,2049,79,25,389,636"
    [UDP]="69,161"
)

# --------------------------
# Core Functions
# --------------------------

# Function to strip color codes
strip_colors() {
    sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"
}

# Function to add a timestamp to each line
add_timestamp() {
    while IFS= read -r line; do
        echo "[$(date '+%Y-%m-%d %H:%M:%S')]   $line"
    done
}

# Status indicators
status_start() {
    local activity="$1"
    echo -e "[..] $activity" | strip_colors | add_timestamp >> "$log_file"
    echo -ne "${blue}[..] $activity${normal}"
}

status_end() {
    if [ $1 -eq 0 ]; then
        echo -e "\r${green}[OK]${normal}"
    else
        echo -e "\r${red}[FAIL]${normal}"
    fi
}

# Error handling
error_exit() {
    echo -e "[ERROR] $1" | strip_colors | add_timestamp >> "$log_file"
    echo -e "${red}[ERROR] $1${normal}" >&2
    exit 1
}

# Run a command with a timeout
run_with_timeout() {
    local timeout=$1
    local command=("${@:2}")
    
    timeout "$timeout" "${command[@]}" >/dev/null 2>&1
    local exit_code=$?
    
    if [ $exit_code -eq 124 ]; then
        error_exit "Command timed out after $timeout seconds"
    elif [ $exit_code -ne 0 ]; then
        error_exit "Command failed with exit code $exit_code"
    fi
}

# Initialize project structure
init_project() {
    
    mkdir -p "$project_base" || error_exit "Failed to create project directory"
    echo "Logs for project: $project_base" >> "$log_file"
    
    # Redirect all output to the log file, stripping color codes (removed as doesnt work properly)
    # exec > >(tee >(strip_colors | add_timestamp >> "$log_file")) 2>&1
    
    status_start "Initializing project structure"
    
    mkdir -p "$project_base/evidence" || error_exit "Failed to create project directory"
    mkdir -p "$project_base/services" || error_exit "Failed to create services directory"
    
    status_end $?
}

# --------------------------
# Validation Functions
# --------------------------
validate_input() {
    status_start "Validating input file"
    
    [ -f "$1" ] || error_exit "Input file not found"
    [ -s "$1" ] || error_exit "Input file is empty"
    
    if grep -q "<?xml" "$1" && grep -q "Nessus" "$1"; then
        input_type="nessus"
    else
        input_type="iplist"
    fi
    
    status_end 0
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if ((octet < 0 || octet > 255)); then
                return 1  # Invalid IP
            fi
        done
        return 0  # Valid IP
    else
        return 1  # Invalid format
    fi
}

# Function to validate CIDR range
validate_cidr() {
    local cidr=$1
    if [[ $cidr =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        local ip=${cidr%/*}
        local mask=${cidr#*/}
        if validate_ip "$ip" && ((mask >= 0 && mask <= 32)); then
            return 0  # Valid CIDR
        fi
    fi
    return 1  # Invalid CIDR
}

# Function to validate IP/CIDR list in the input file
validate_ip_list() {
    local input_file=$1
    status_start "Validating IP addresses/ranges in input file"
    
    while read -r line; do
        if ! validate_ip "$line" && ! validate_cidr "$line"; then
            error_exit "Invalid IP address or CIDR range: $line"
        fi
    done < "$input_file"

    status_end 0
}

# --------------------------
# Scanning Functions
# --------------------------
run_service_scan() {

    local targets=$1
    mkdir -p "$project_base/nmap" || error_exit "Failed to create nmap folder in project directory"
    status_start "Running TCP/UDP scans with Nmap (might take a while)"
    echo "Running command: nmap -p ${PORTS[TCP]} --open -iL $targets -oG $project_base/nmap/tcp_scan.gnmap" | strip_colors | add_timestamp >> "$log_file"
    run_with_timeout $SCAN_TIMEOUT nmap -p ${PORTS[TCP]} --open -iL "$targets" -oG "$project_base/nmap/tcp_scan.gnmap"
    echo "Running command: nmap -p ${PORTS[UDP]} --open -iL $targets -oG $project_base/nmap/udp_scan.gnmap" | strip_colors | add_timestamp >> "$log_file"
    run_with_timeout $SCAN_TIMEOUT nmap -sU -p ${PORTS[UDP]} -iL "$targets" -oG "$project_base/nmap/udp_scan.gnmap"

    # Extract targets from scan results
    grep -ohP 'Host: \K[^ ]+' "$project_base/nmap/tcp_scan.gnmap" "$project_base/nmap/udp_scan.gnmap" | sort -u > "$project_base/targets.txt"
    
    status_end $?
}

# --------------------------
# Services Extraction Functions
# --------------------------

# Function to extract services from Nmap scan results
extract_services() {
    status_start "Extracting services from scan results"
    
    # Ensure the Services folder exists
    mkdir -p "$project_base/services"
    
    # Parse the TCP scan results
    if [ -f "$project_base/nmap/tcp_scan.gnmap" ]; then
        while read -r line; do
            ip=$(echo "$line" | awk '{print $2}')
            ports=$(echo "$line" | grep -oP '\d+/open/[^ ]+')
            
            for port in $ports; do
                port_num=$(echo "$port" | cut -d'/' -f1)
                service=$(echo "$port" | cut -d'/' -f5 | tr '[:lower:]' '[:upper:]')
                
                # Create a file for the service if it doesn't exist
                if [ ! -f "$project_base/services/$service.txt" ]; then
                    touch "$project_base/services/$service.txt"
                fi
                
                # Append the IP and port to the service file
                echo "$ip:$port_num" >> "$project_base/services/$service.txt"
            done
        done < "$project_base/nmap/tcp_scan.gnmap"
    fi
    
    # Parse the UDP scan results
    if [ -f "$project_base/udp_scan.gnmap" ]; then
        while read -r line; do
            ip=$(echo "$line" | awk '{print $2}')
            ports=$(echo "$line" | grep -oP '\d+/open/[^ ]+')
            
            for port in $ports; do
                port_num=$(echo "$port" | cut -d'/' -f1)
                service=$(echo "$port" | cut -d'/' -f5 | tr '[:lower:]' '[:upper:]')
                
                # Create a file for the service if it doesn't exist
                if [ ! -f "$project_base/services/$service.txt" ]; then
                    touch "$project_base/services/$service.txt"
                fi
                
                # Append the IP and port to the service file
                echo "$ip:$port_num" >> "$project_base/services/$service.txt"
            done
        done < "$project_base/udp_scan.gnmap"
    fi
    
    status_end $?
}

# --------------------------
# Service Enumeration Functions
# --------------------------

# Function to enumerate HTTP/HTTPS services
enumerate_http_https() {
    status_start "Enumerating HTTP/HTTPS services"
    
    if [ -f "$project_base/services/HTTP.txt" ]; then
        mkdir -p "$project_base/evidence/HTTP"
        awk -F':' '/:80/ {print "http://"$1":"$2}' "$project_base/services/HTTP.txt" >> "$project_base/evidence/URLs.txt"
        echo "[CONFIRMED] Cleartext HTTP in use." >> "$project_base/evidence/vulnerabilities.txt"
    fi
    
    if [ -f "$project_base/services/HTTPS.txt" ]; then
        mkdir -p "$project_base/evidence/HTTPS"
        awk -F':' '/:443/ {print "https://"$1":"$2}' "$project_base/services/HTTPS.txt" >> "$project_base/evidence/URLs.txt"
    fi
    
     # Run Eyewitness if installed
     if command -v eyewitness &>/dev/null; then
	echo "Running Eyewitness on web services..." | strip_colors | add_timestamp >> "$log_file" # Log Eyewitness execution
	    eyewitness --no-prompt --web -f "$project_base/evidence/URLs.txt" -d "$project_base/evidence/Eyewitness" >/dev/null 2>&1
	    if [ $? -eq 0 ]; then
		echo "Eyewitness completed successfully." | strip_colors | add_timestamp >> "$log_file"
	    else
		echo "Eyewitness failed." | strip_colors | add_timestamp >> "$log_file"
	    fi
	else
	    echo "Eyewitness not installed. Skipping HTTP/HTTPS screenshots." | strip_colors | add_timestamp >> "$log_file"
	fi
    
    status_end $?
}

# Function to enumerate SSH services
enumerate_ssh() {
    status_start "Enumerating SSH services"
    
    if [ -s "$project_base/services/SSH.txt" ]; then
        mkdir -p "$project_base/evidence/SSH"
        while read -r target; do
            ip=$(echo "$target" | cut -d':' -f1)
            
            # Log the tool execution
            echo "Running Nmap on $ip for SSH enumeration..." | strip_colors | add_timestamp >> "$log_file"
            
            nmap -p 22 -sV --script ssh-auth-methods,ssh2-enum-algos "$ip" -oN "$project_base/evidence/SSH/$ip-SSH-Config.txt" >/dev/null 2>&1
            
            # Log the result
            if [ $? -eq 0 ]; then
                echo "Nmap completed successfully for $ip." | strip_colors | add_timestamp >> "$log_file"
            else
                echo "Nmap failed for $ip." | strip_colors | add_timestamp >> "$log_file"
            fi
        done < "$project_base/services/SSH.txt"
        
        echo "[POTENTIAL] SSH Password Authentication, vulnerable to brute-force." >> "$project_base/evidence/vulnerabilities.txt"
        echo "[POTENTIAL] Weak SSH Ciphers and Key-Exchange Algorithms." >> "$project_base/evidence/vulnerabilities.txt"
    else
        echo "No SSH services found." | add_timestamp >> "$log_file"
    fi
    
    status_end $?
}

# Function to enumerate SMB services
enumerate_smb() {
    status_start "Enumerating SMB services"
    
    if [ -f "$project_base/services/SMB.txt" ]; then
        cut -d ":" -f1 "$project_base/services/SMB.txt" > "$project_base/evidence/.smb-targets.tmp"
        
        nmap --script "safe or smb-enum-*" -p 445 -iL "$project_base/evidence/.smb-targets.tmp" -oN "$project_base/evidence/SMB-Enumeration.txt" >/dev/null 2>&1
        echo "[POTENTIAL] Check if any obsolete SMBv1 services are present." >> "$project_base/evidence/vulnerabilities.txt"
        
        # Check for SMB Signing disabled
        nmap -Pn -n -iL "$project_base/evidence/.smb-targets.tmp" -p445 --script=smb-security-mode -oN "$project_base/evidence/.smb-signing.tmp" >/dev/null 2>&1
        grep "disabled" "$project_base/evidence/.smb-signing.tmp" -B 15 | grep "for" | cut -d " " -f5 > "$project_base/evidence/SMB-Signing-Disabled.txt"
        
        echo "[CONFIRMED] Hosts with SMB Signing disabled or not required." >> "$project_base/evidence/vulnerabilities.txt"
        echo "[POTENTIAL] Check accessible SMB shares for sensitive content." >> "$project_base/evidence/vulnerabilities.txt"
        
        rm "$project_base/evidence/.smb-targets.tmp" "$project_base/evidence/.smb-signing.tmp" 2>/dev/null
    fi
    
    status_end $?
}

# Function to enumerate SNMP services
enumerate_snmp() {
    status_start "Enumerating SNMP services"
    
    if [ -f "$project_base/services/SNMP.txt" ]; then
        if command -v snmp-check &>/dev/null; then
            mkdir -p "$project_base/evidence/SNMP-Checks"
            while read -r target; do
                snmp-check "$target" > "$project_base/evidence/SNMP-Checks/$target-snmp.txt"
            done < <(cut -d ":" -f1 "$project_base/services/SNMP.txt")
            
            echo "[CONFIRMED] Cleartext protocols in use." >> "$project_base/evidence/vulnerabilities.txt"
            echo "[POTENTIAL] Check default community strings on SNMP services." >> "$project_base/evidence/vulnerabilities.txt"
        else
            echo "[INFO] SNMP-Check not installed. Skipping SNMP enumeration." >> "$project_base/evidence/vulnerabilities.txt"
        fi
    fi
    
    status_end $?
}

# Function to enumerate FTP services
enumerate_ftp() {
    status_start "Enumerating FTP services"
    
    if [ -f "$project_base/services/FTP.txt" ]; then
        cut -d ":" -f1 "$project_base/services/FTP.txt" > "$project_base/evidence/.ftp-targets.tmp"
        
        nmap -Pn -n -iL "$project_base/evidence/.ftp-targets.tmp" -p21 -sC -oN "$project_base/evidence/FTP-Checks.txt" >/dev/null 2>&1
        echo "[POTENTIAL] Check for anonymous access on FTP services." >> "$project_base/evidence/vulnerabilities.txt"
        echo "[CONFIRMED] Cleartext protocols in use." >> "$project_base/evidence/vulnerabilities.txt"
        
        rm "$project_base/evidence/.ftp-targets.tmp" 2>/dev/null
    fi
    
    status_end $?
}

# Function to enumerate VNC services
enumerate_vnc() {
    status_start "Enumerating VNC services"
    
    if [ -f "$project_base/services/VNC.txt" ]; then
        cut -d ":" -f1 "$project_base/services/VNC.txt" > "$project_base/evidence/.vnc-targets.tmp"
        
        nmap -Pn -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p 5900,5901 -iL "$project_base/evidence/.vnc-targets.tmp" -oN "$project_base/evidence/VNC-Checks.txt" >/dev/null 2>&1
        echo "[POTENTIAL] Check for any unauthenticated VNC services." >> "$project_base/evidence/vulnerabilities.txt"
        
        rm "$project_base/evidence/.vnc-targets.tmp" 2>/dev/null
    fi
    
    status_end $?
}

# Function to enumerate TFTP services
enumerate_tftp() {
    status_start "Enumerating TFTP services"
    
    if [ -f "$project_base/services/TFTP.txt" ]; then
        cut -d ":" -f1 "$project_base/services/TFTP.txt" > "$project_base/evidence/.tftp-targets.tmp"
        
        nmap -Pn -sU -p69 -sV --script tftp-enum -iL "$project_base/evidence/.tftp-targets.tmp" -oN "$project_base/evidence/TFTP-Checks.txt" >/dev/null 2>&1
        echo "[POTENTIAL] Check for exposed TFTP services." >> "$project_base/evidence/vulnerabilities.txt"
        
        rm "$project_base/evidence/.tftp-targets.tmp" 2>/dev/null
    fi
    
    status_end $?
}

# Function to enumerate TELNET services
enumerate_telnet() {
    status_start "Enumerating TELNET services"
    
    if [ -f "$project_base/services/TELNET.txt" ]; then
        cut -d ":" -f1 "$project_base/services/TELNET.txt" > "$project_base/evidence/.telnet-targets.tmp"
        
        nmap -sV -Pn --script "*telnet*" -p 23 -iL "$project_base/evidence/.telnet-targets.tmp" -oN "$project_base/evidence/TELNET-Checks.txt" >/dev/null 2>&1
        echo "[CONFIRMED] Cleartext protocols in use." >> "$project_base/evidence/vulnerabilities.txt"
        
        rm "$project_base/evidence/.telnet-targets.tmp" 2>/dev/null
    fi
    
    status_end $?
}

# Function to enumerate NFS services
enumerate_nfs() {
    status_start "Enumerating NFS services"
    
    if [ -f "$project_base/services/NFS.txt" ]; then
        cut -d ":" -f1 "$project_base/services/NFS.txt" > "$project_base/evidence/.nfs-targets.tmp"
        
        nmap -Pn --script=nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse -p 2049 -iL "$project_base/evidence/.nfs-targets.tmp" -oN "$project_base/evidence/NFS-Checks.txt" >/dev/null 2>&1
        echo "[POTENTIAL] Check content of any NFS shares for sensitive data." >> "$project_base/evidence/vulnerabilities.txt"
        
        rm "$project_base/evidence/.nfs-targets.tmp" 2>/dev/null
    fi
    
    status_end $?
}

# Function to enumerate RDP services
enumerate_rdp() {
    status_start "Enumerating RDP services"
    
    if [ -f "$project_base/services/RDP.txt" ]; then
        cut -d ":" -f1 "$project_base/services/RDP.txt" > "$project_base/evidence/.rdp-targets.tmp"
        
        nmap -sV -Pn --script "rdp*" -p 3389 -iL "$project_base/evidence/.rdp-targets.tmp" -oN "$project_base/evidence/RDP-Checks.txt" >/dev/null 2>&1
        echo "[POTENTIAL] Check if NLA is implemented for RDP services." >> "$project_base/evidence/vulnerabilities.txt"
        
        rm "$project_base/evidence/.rdp-targets.tmp" 2>/dev/null
    fi
    
    status_end $?
}

# Function to enumerate FINGER services
enumerate_finger() {
    status_start "Enumerating FINGER services"
    
    if [ -f "$project_base/services/FINGER.txt" ]; then
        cut -d ":" -f1 "$project_base/services/FINGER.txt" > "$project_base/evidence/.finger-targets.tmp"
        
        nmap -Pn -sV -sC -p 79 -iL "$project_base/evidence/.finger-targets.tmp" -oN "$project_base/evidence/FINGER-Checks.txt" >/dev/null 2>&1
        echo "[POTENTIAL] Check for exposed FINGER services." >> "$project_base/evidence/vulnerabilities.txt"
        
        rm "$project_base/evidence/.finger-targets.tmp" 2>/dev/null
    fi
    
    status_end $?
}

# Function to enumerate SMTP services
enumerate_smtp() {
    status_start "Enumerating SMTP services"
    
    if [ -f "$project_base/services/SMTP.txt" ]; then
        cut -d ":" -f1 "$project_base/services/SMTP.txt" > "$project_base/evidence/.smtp-targets.tmp"
        
        nmap -Pn --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 -iL "$project_base/evidence/.smtp-targets.tmp" -oN "$project_base/evidence/SMTP-Checks.txt" >/dev/null 2>&1
        echo "[CONFIRMED] Cleartext protocols in use." >> "$project_base/evidence/vulnerabilities.txt"
        
        rm "$project_base/evidence/.smtp-targets.tmp" 2>/dev/null
    fi
    
    status_end $?
}

# Function to enumerate LDAP services
enumerate_ldap() {
    status_start "Enumerating LDAP services"
    
    if [ -f "$project_base/services/LDAP.txt" ]; then
        cut -d ":" -f1 "$project_base/services/LDAP.txt" > "$project_base/evidence/.ldap-targets.tmp"
        
        nmap -Pn -n -p 389 --script "ldap* and not brute" -iL "$project_base/evidence/.ldap-targets.tmp" -oN "$project_base/evidence/LDAP-Checks.txt" >/dev/null 2>&1
        echo "[POTENTIAL] Check for anonymous LDAP access." >> "$project_base/evidence/vulnerabilities.txt"
        
        rm "$project_base/evidence/.ldap-targets.tmp" 2>/dev/null
    fi
    
    status_end $?
}

# Function to enumerate LDAPS services
enumerate_ldaps() {
    status_start "Enumerating LDAPS services"
    
    if [ -f "$project_base/services/LDAPS.txt" ]; then
        cut -d ":" -f1 "$project_base/services/LDAPS.txt" > "$project_base/evidence/.ldaps-targets.tmp"
        
        nmap -Pn -n -p 636 --script "ldap* and not brute" -iL "$project_base/evidence/.ldaps-targets.tmp" -oN "$project_base/evidence/LDAPS-Checks.txt" >/dev/null 2>&1
        echo "[POTENTIAL] Check for misconfigured LDAPS services." >> "$project_base/evidence/vulnerabilities.txt"
        
        rm "$project_base/evidence/.ldaps-targets.tmp" 2>/dev/null
    fi
    
    status_end $?
}

# Function to enumerate KERBEROS services
enumerate_kerberos() {
    status_start "Enumerating KERBEROS services"
    
    if [ -f "$project_base/services/KERBEROS.txt" ]; then
        cut -d ":" -f1 "$project_base/services/KERBEROS.txt" > "$project_base/evidence/.kerberos-targets.tmp"
        
        nmap -Pn -n -p 88 --script krb5-enum-users -iL "$project_base/evidence/.kerberos-targets.tmp" -oN "$project_base/evidence/KERBEROS-Checks.txt" >/dev/null 2>&1
        echo "[POTENTIAL] Check for Kerberos user enumeration vulnerabilities." >> "$project_base/evidence/vulnerabilities.txt"
        
        rm "$project_base/evidence/.kerberos-targets.tmp" 2>/dev/null
    fi
    
    status_end $?
}

# Function to enumerate all services
enumerate_services() {

    # HTTP/HTTPS
    if [ -f "$project_base/services/HTTP.txt" ] || [ -f "$project_base/services/HTTPS.txt" ]; then
        enumerate_http_https
    fi

    # SSH
    if [ -f "$project_base/services/SSH.txt" ]; then
        enumerate_ssh
    fi

    # SMB
    if [ -f "$project_base/services/SMB.txt" ]; then
        enumerate_smb
    fi

    # SNMP
    if [ -f "$project_base/services/SNMP.txt" ]; then
        enumerate_snmp
    fi

    # FTP
    if [ -f "$project_base/services/FTP.txt" ]; then
        enumerate_ftp
    fi

    # VNC
    if [ -f "$project_base/services/VNC.txt" ]; then
        enumerate_vnc
    fi

    # TFTP
    if [ -f "$project_base/services/TFTP.txt" ]; then
        enumerate_tftp
    fi

    # TELNET
    if [ -f "$project_base/services/TELNET.txt" ]; then
        enumerate_telnet
    fi

    # NFS
    if [ -f "$project_base/services/NFS.txt" ]; then
        enumerate_nfs
    fi

    # RDP
    if [ -f "$project_base/services/RDP.txt" ]; then
        enumerate_rdp
    fi

    # FINGER
    if [ -f "$project_base/services/FINGER.txt" ]; then
        enumerate_finger
    fi

    # SMTP
    if [ -f "$project_base/services/SMTP.txt" ]; then
        enumerate_smtp
    fi

    # LDAP
    if [ -f "$project_base/services/LDAP.txt" ]; then
        enumerate_ldap
    fi

    # LDAPS
    if [ -f "$project_base/services/LDAPS.txt" ]; then
        enumerate_ldaps
    fi

    # KERBEROS
    if [ -f "$project_base/services/KERBEROS.txt" ]; then
        enumerate_kerberos
    fi
}

# --------------------------
# HTML Report Function
# --------------------------

generate_html_report() {
    status_start "Generating HTML report"
    
    # Declare the HTML file path
    html_file="$project_base/$project_base-report.html"
    
    # Create the HTML file with modern styling
    cat <<EOF > "$html_file"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Internum Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .fade-in { animation: fadeIn 0.3s ease-out; }
        .vulnerability_confirmed { background-color: #fee2e2; border-left: 4px solid #dc2626; }
        .vulnerability_potential { background-color: #fef9c3; border-left: 4px solid #eab308; }
        .vulnerability_info { background-color: #dbeafe; border-left: 4px solid #2563eb; }
    </style>
</head>
<body class="bg-gray-100 text-gray-900">
    <div class="container mx-auto px-4 py-8">
        <!-- Header Section -->
        <header class="mb-8 fade-in">
            <h1 class="text-3xl font-bold text-gray-800 mb-8">Internum - Security Report</h1>
            <div class="bg-white rounded-lg shadow-sm p-6">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <p class="text-sm font-medium text-gray-500">Project Name</p>
                        <p class="text-gray-800">$project_base</p>
                    </div>
                    <div>
                        <p class="text-sm font-medium text-gray-500">Scan Duration</p>
                        <p class="text-gray-800">$starttime - $(date)</p>
                    </div>
                </div>
            </div>
        </header>

        <!-- Main Content -->
        <div class="space-y-8">
            <!-- Service Summary -->
            <section class="fade-in">
                <div class="bg-white rounded-lg shadow-sm p-6">
                    <h2 class="text-xl font-semibold text-gray-800 mb-4">Service Overview</h2>
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
EOF

    # Add service summary
    for service_file in "$project_base/services/"*.txt; do
        if [ -f "$service_file" ]; then
            service_name=$(basename "$service_file" .txt)
            host_count=$(wc -l < "$service_file")
            cat <<EOF >> "$html_file"
                        <div class="bg-gray-50 p-4 rounded-lg">
                            <p class="text-sm text-gray-500">$service_name</p>
                            <p class="text-2xl font-bold text-gray-800">$host_count</p>
                        </div>
EOF
        fi
    done

    cat <<EOF >> "$html_file"
                    </div>
                </div>
            </section>

            <!-- Discovered Hosts -->
            <section class="fade-in">
                <div class="bg-white rounded-lg shadow-sm p-6">
                    <h2 class="text-xl font-semibold text-gray-800 mb-4">Discovered Hosts</h2>
                    <div class="overflow-x-auto">
                        <table class="w-full">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-gray-500">IP Address</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-gray-500">Hostname</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-gray-500">Open Ports</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-200">
EOF

    # Add hosts and services
    if [ -f "$project_base/targets.txt" ]; then
        while read -r host; do
            services=$(grep -h "\b$host\b" "$project_base/nmap/tcp_scan.gnmap" "$project_base/nmap/udp_scan.gnmap" 2>/dev/null | 
                      grep -oP '\d+/open/[^ ]+' | cut -d "/" -f1,3)
            hostname=$(nslookup "$host" 2>/dev/null | grep "name =" | awk '{print $4}')
            cat <<EOF >> "$html_file"
                                <tr>
                                    <td class="px-4 py-3 text-sm text-gray-800">$host</td>
                                    <td class="px-4 py-3 text-sm text-gray-800">${hostname:-N/A}</td>
                                    <td class="px-4 py-3 text-sm text-gray-800"><div class="flex flex-wrap gap-2">$(echo "$services" | sed 's/ /<\/div><div class="bg-gray-100 px-2 py-1 rounded text-xs">/g')</div></td>
                                </tr>
EOF
        done < "$project_base/targets.txt"
    else
        cat <<EOF >> "$html_file"
                                <tr>
                                    <td colspan="3" class="px-4 py-3 text-sm text-gray-500 text-center">No hosts found</td>
                                </tr>
EOF
    fi

    cat <<EOF >> "$html_file"
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>

            <!-- Vulnerabilities -->
            <section class="fade-in">
                <div class="bg-white rounded-lg shadow-sm p-6">
                    <h2 class="text-xl font-semibold text-gray-800 mb-4">Security Findings</h2>
                    <div class="space-y-3">
EOF

    # Add vulnerabilities
    if [ -f "$project_base/evidence/vulnerabilities.txt" ]; then
        while read -r vulnerability; do
            class="vulnerability_info"
            [[ "$vulnerability" == "[CONFIRMED]"* ]] && class="vulnerability_confirmed"
            [[ "$vulnerability" == "[POTENTIAL]"* ]] && class="vulnerability_potential"
            
            cat <<EOF >> "$html_file"
                        <div class="$class p-4 rounded-lg flex items-start space-x-3">
                            <div class="flex-1">
                                <p class="text-sm font-medium text-gray-700">$vulnerability</p>
                            </div>
                        </div>
EOF
        done < "$project_base/evidence/vulnerabilities.txt"
    else
        cat <<EOF >> "$html_file"
                        <div class="bg-gray-50 p-4 rounded-lg text-center">
                            <p class="text-sm text-gray-500">No vulnerabilities found</p>
                        </div>
EOF
    fi

    cat <<EOF >> "$html_file"
                    </div>
                </div>
            </section>

            <!-- Evidence Section -->
            <section class="fade-in">
                <div class="bg-white rounded-lg shadow-sm p-6">
                    <h2 class="text-xl font-semibold text-gray-800 mb-4">Evidence Collection</h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                            <h3 class="text-sm font-medium text-gray-500 mb-3">Files</h3>
                            <div class="space-y-2">
EOF

    # Add evidence files
    for file in "$project_base/evidence/"*; do
        if [ -f "$file" ] && [ "$(basename "$file")" != "report.html" ]; then
            file_name=$(basename "$file")
            cat <<EOF >> "$html_file"
                                <a href="$file_name" class="flex items-center justify-between p-3 bg-gray-50 hover:bg-gray-100 rounded-lg transition-colors">
                                    <span class="text-sm text-gray-800">$file_name</span>
                                    <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>
                                    </svg>
                                </a>
EOF
        fi
    done

    cat <<EOF >> "$html_file"
                            </div>
                        </div>
                        <div>
                            <h3 class="text-sm font-medium text-gray-500 mb-3">Service Directories</h3>
                            <div class="space-y-2">
EOF

    # Add service-specific evidence folders
    for service_folder in "$project_base/evidence/"*/; do
        if [ -d "$service_folder" ]; then
            service_name=$(basename "$service_folder")
            cat <<EOF >> "$html_file"
                                <a href="$service_name" class="flex items-center justify-between p-3 bg-gray-50 hover:bg-gray-100 rounded-lg transition-colors">
                                    <span class="text-sm text-gray-800">$service_name/</span>
                                    <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>
                                    </svg>
                                </a>
EOF
        fi
    done

    cat <<EOF >> "$html_file"
                            </div>
                        </div>
                    </div>
                    <div class="mt-6 text-sm text-gray-500">
                        Complete activity log available in: <a href="./internum.log" class="text-blue-600 hover:text-blue-800">internum.log</a>
                    </div>
                </div>
            </section>
        </div>
    </div>
</body>
</html>
EOF

    status_end $?
}

# --------------------------
# Help Facility
# --------------------------
show_help() {
    echo -e "${bold}Usage:${normal} $0 [OPTIONS] <input_file>"
    echo
    echo -e "${bold}Options:${normal}"
    echo -e "  -h, --help    Show this help message and exit"
    echo
    echo -e "${bold}Description:${normal}"
    echo -e "  This script performs internal infrastructure assessments by scanning and enumerating services."
    echo -e "  It supports input files containing IP addresses/ranges or Nessus scan exports."
    echo
    echo -e "${bold}Examples:${normal}"
    echo -e "  $0 targets.txt"
    echo -e "  $0 scan.nessus (Coming Soon)"
    exit 0
}

# --------------------------
# Banner
# --------------------------

banner() {
	clear
	echo -e $green               
	echo -e "    _       __                                "
	echo -e "   (_)___  / /____  _________  __  __________ "
	echo -e "  / / __ \/ __/ _ \/ ___/ __ \/ / / / __  __ \\"
	echo -e " / / / / / /_/  __/ /  / / / / /_/ / / / / / /"
	echo -e "/_/_/ /_/\__/\___/_/  /_/ /_/\__,_/_/ /_/ /_/ "
	echo -e "        by W3155 - 2025 - Version:1.2" 
	echo -e $normal
}

# --------------------------
# Main Execution Flow
# --------------------------
main() {

    banner
    
    # Show help if no arguments or -h/--help provided
    if [ $# -eq 0 ] || [[ "$1" == "-h" || "$1" == "--help" ]]; then
        show_help
    fi

    # Initial validations
    [ $(id -u) -eq 0 ] || error_exit "Root privileges required"
    [ $# -ge 1 ] || error_exit "No input file specified"
    
    starttime=$(date)
    
    # Setup environment
    init_project
    validate_input "$1"  # Input File validation
    validate_ip_list "$1"  # IP/CIDR Targets validation
    
    # Run nmap scan
    run_service_scan "$1"
    
    # Extract services from scan results
    extract_services
    
    # Enumerate services
    enumerate_services
    
    # Generate HTML report
    generate_html_report
    
    echo -e "${blue}\nProject saved in: ${normal}" $project_base
    echo -e "${blue}See report and logs for further details.${normal}"
    echo "Program finished." | add_timestamp >> "$log_file"
}

# --------------------------
# Start Execution
# --------------------------
main "$@"
