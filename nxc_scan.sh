#!/bin/bash

# Color codes for output
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
RESET="\e[0m"

# Updated available protocols (including NFS)
PROTOCOLS=("rdp" "ldap" "winrm" "smb" "ssh" "nfs" "ftp" "wmi" "mssql" "vnc")

# Help menu
print_help() {
    echo -e "${BLUE}\nNXC Service Scanner Automation${RESET}"
    echo -e "${YELLOW}Automates enumeration of Active Directory services using NXC.${RESET}"
    echo -e "\n${MAGENTA}Usage:${RESET}"
    echo -e "  ./nxc_scan.sh -r <RHOST> -u <USERNAME> -p <PASSWORD> [-U <USERFILE>] [-P <PASSFILE>] [-H <HASHFILE>] -s <services>"
    echo -e "\n${MAGENTA}Options:${RESET}"
    echo -e "  -r, --RHOST         Target IP address or hostname"
    echo -e "  -u, --USERNAME      Username for authentication"
    echo -e "  -p, --PASSWORD      Password for authentication"
    echo -e "  -H, --HASH          NT Hash for authentication"
    echo -e "  -U, --USERFILE      File containing multiple usernames"
    echo -e "  -P, --PASSFILE      File containing multiple passwords"
    echo -e "  -s, --SERVICES      Comma-separated list of services to scan (Available: ${PROTOCOLS[*]})"
    echo -e "\n${MAGENTA}Example Usage:${RESET}"
    echo -e "  ./nxc_scan.sh -r 10.10.11.42 -u admin -p MyPassword -s smb,winrm"
    echo -e "  ./nxc_scan.sh -r 10.10.11.42 -U users.txt -H hashes.txt -s rdp,ldap,winrm,smb,ssh,ftp,mssql,wmi,vnc,nfs"
    echo -e "\n${BLUE}The script will automatically perform local and regular authentication.${RESET}"
    exit 0
}

# Check if no arguments were provided
if [[ $# -eq 0 ]]; then
    print_help
fi

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -r|--RHOST)
            RHOST="$2"
            shift; shift ;;
        -u|--USERNAME)
            USER_INPUT="$2"
            shift; shift ;;
        -p|--PASSWORD)
            PASS_INPUT="$2"
            AUTH_TYPE="password"
            shift; shift ;;
        -H|--HASH)
            HASH_INPUT="$2"
            AUTH_TYPE="hash"
            shift; shift ;;
        -U|--USERFILE)
            USERFILE="$2"
            shift; shift ;;
        -P|--PASSFILE)
            PASSFILE="$2"
            shift; shift ;;
        -s|--SERVICES)
            SERVICES="$2"
            shift; shift ;;
        -h|--help)
            print_help ;;
        *)
            echo -e "${RED}[ERROR] Unknown option: $1${RESET}"
            print_help ;;
    esac
done

# Validate required inputs
if [[ -z "$RHOST" || -z "$SERVICES" ]]; then
    echo -e "${RED}[ERROR] Missing required arguments: --RHOST and --SERVICES are mandatory!${RESET}"
    print_help
fi

# Function to check if input is a file and load its contents
load_credentials() {
    local input="$1"
    local credentials=()
    if [[ -f "$input" ]]; then
        while IFS= read -r line; do
            credentials+=("$line")
        done < "$input"
    else
        credentials+=("$input")
    fi
    echo "${credentials[@]}"
}

# Load usernames
if [[ -n "$USERFILE" ]]; then
    USERNAMES=($(load_credentials "$USERFILE"))
elif [[ -n "$USER_INPUT" ]]; then
    USERNAMES=("$USER_INPUT")
else
    echo -e "${RED}[ERROR] No username or username file provided.${RESET}"
    exit 1
fi

# Load passwords or hashes
if [[ "$AUTH_TYPE" == "password" ]]; then
    if [[ -n "$PASSFILE" ]]; then
        PASSWORDS=($(load_credentials "$PASSFILE"))
    elif [[ -n "$PASS_INPUT" ]]; then
        PASSWORDS=("$PASS_INPUT")
    else
        echo -e "${RED}[ERROR] No password or password file provided.${RESET}"
        exit 1
    fi
elif [[ "$AUTH_TYPE" == "hash" ]]; then
    HASHES=($(load_credentials "$HASH_INPUT"))
else
    echo -e "${RED}[ERROR] No authentication method selected! Use -p for password or -H for NT Hash.${RESET}"
    exit 1
fi

# Convert services to an array
IFS=',' read -r -a SERVICE_LIST <<< "$SERVICES"

# Validate services
for service in "${SERVICE_LIST[@]}"; do
    if [[ ! " ${PROTOCOLS[*]} " =~ " $service " ]]; then
        echo -e "${RED}[ERROR] Invalid service: $service${RESET}"
        exit 1
    fi
done

# Run scans with local and domain authentication
for service in "${SERVICE_LIST[@]}"; do
    for user in "${USERNAMES[@]}"; do
        if [[ "$AUTH_TYPE" == "password" ]]; then
            for pass in "${PASSWORDS[@]}"; do
                echo -e "${YELLOW}Scanning ${service^^} on $RHOST with $user...${RESET}"
                
                # SMB & NFS need --shares for listing shares
                if [[ "$service" == "smb" ]]; then
                    nxc "$service" "$RHOST" -u "$user" -p "$pass" --shares --continue-on-success
                    nxc "$service" "$RHOST" -u "$user" -p "$pass" --local-auth --shares --continue-on-success
                    nxc "$service" "$RHOST" -u "$user" -p "$pass" --shares
                    nxc "$service" "$RHOST" -u "$user" -p "$pass" --local-auth --shares
                elif [[ "$service" == "nfs" ]]; then
                    nxc "$service" "$RHOST" --shares --continue-on-success
                elif [[ "$service" == "ssh" || "$service" == "ftp" ]]; then
                    nxc "$service" "$RHOST" -u "$user" -p "$pass" --continue-on-success
                else
                    nxc "$service" "$RHOST" -u "$user" -p "$pass" --continue-on-success
                    nxc "$service" "$RHOST" -u "$user" -p "$pass" --local-auth --continue-on-success
                fi
            done
        elif [[ "$AUTH_TYPE" == "hash" ]]; then
            for hash in "${HASHES[@]}"; do
                echo -e "${YELLOW}Scanning ${service^^} on $RHOST with $user (NT Hash)...${RESET}"
                
                if [[ "$service" == "smb" ]]; then
                    nxc "$service" "$RHOST" -u "$user" -H "$hash" --shares --continue-on-success
                    nxc "$service" "$RHOST" -u "$user" -H "$hash" --local-auth --shares --continue-on-success
                    nxc "$service" "$RHOST" -u "$user" -H "$hash" --local-auth --shares
                    nxc "$service" "$RHOST" -u "$user" -H "$hash" --shares
                elif [[ "$service" == "nfs" ]]; then
                    nxc "$service" "$RHOST" --shares --continue-on-success
                elif [[ "$service" == "ssh" || "$service" == "ftp" ]]; then
                    nxc "$service" "$RHOST" -u "$user" -H "$hash" --continue-on-success
                else
                    nxc "$service" "$RHOST" -u "$user" -H "$hash" --continue-on-success
                    nxc "$service" "$RHOST" -u "$user" -H "$hash" --local-auth --continue-on-success
                fi
            done
        fi
    done
done

echo -e "${GREEN}Scanning complete.${RESET}"
