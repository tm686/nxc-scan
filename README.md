# nxc-scan
A simple script to spray creds and passwords over netexec services. 
A better and more advanced script can be found here https://github.com/overgrowncarrot1/Netexec_Auto_Hacks and https://github.com/overgrowncarrot1/CrackEverything6
```
NXC Service Scanner Automation
Automates enumeration of Active Directory services using NXC.

Usage:
  ./nxc_scan.sh -r <RHOST> -u <USERNAME> -p <PASSWORD> [-U <USERFILE>] [-P <PASSFILE>] [-H <HASHFILE>] -s <services>

Options:
  -r, --RHOST         Target IP address or hostname
  -u, --USERNAME      Username for authentication
  -p, --PASSWORD      Password for authentication
  -H, --HASH          NT Hash for authentication
  -U, --USERFILE      File containing multiple usernames
  -P, --PASSFILE      File containing multiple passwords
  -s, --SERVICES      Comma-separated list of services to scan (Available: rdp ldap winrm smb ssh nfs ftp wmi mssql vnc)

Example Usage:
  ./nxc_scan.sh -r 10.10.11.42 -u admin -p MyPassword -s smb,winrm
  ./nxc_scan.sh -r 10.10.11.42 -U users.txt -H hashes.txt -s rdp,ldap,winrm,smb,ssh,ftp,mssql,wmi,vnc,nfs
```
