#!/usr/bin/python3

import nmap3
import re
import requests
from ftplib import FTP
import ipaddress

VERBOSE=False #Debugging typeshiit
args="-sV -p21,22,23,80,443 --script ssl-enum-ciphers"

def validate_ip(ip_string):
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def ftp_anon(host): #forced to do it cz nmap script ftp-anon aint working *_*
    try:        
        ftp = FTP(timeout=5)
        ftp.connect(host,21)
        ftp.login('anonymous','anonymous@')
        ftp.quit()
        return 1
    except Exception as e:
        print(f"can't connect to ftp anonymously : {e}")
        return 0

def check_redirect(target): #again http-redirection script doesnt work so forced to test it here xd 
    r = requests.get("http://"+target, allow_redirects=False, timeout=5)
    return r.status_code

def check_ver(version):
    match = re.search(r"(\d+\.\d+)", version)
    if match:
        version_num = float(match.group(1))
        if version_num >= 7.4:
            return 1
        else:
            return 0
    else:
        print(f"[!]Couldnt get the version of the string , try to check manually:")
        print(f"=>{version}")
        return None


def tls_check(ver):
    
    for tls_version in ['TLSv1.0', 'TLSv1.1']:
        if tls_version in ver and ver[tls_version]['ciphers']['children']:
            return False  
    
    return True



def scan(target):
    try:
        nmap = nmap3.NmapHostDiscovery()
        results = nmap.nmap_portscan_only(target,args)
        for port in results[target]["ports"]:
            
            if port["portid"]=="23":
                if port["state"]=="closed":
                    print("[PASS] Port 23 is closed => No telnet service.")
                else:
                    print("[WARNING] Port 23 is not closed => Telnet service is available !")
        
            if port["portid"]=="22":
                if port["state"]=="open":        
                    if check_ver(port["service"]["version"]):
                        print("[PASS] ssh service is updated => ssh version >= 7.4")
                    elif not check_ver(port["service"]["version"]):
                        print("[WARNING] Your ssh version is very old => ssh version <=7.4")
                        print("========> MUST update !")
                else:
                    print("[PASS] ssh is diabled *-*/")

            if port["portid"]=="80" and port["state"] == "open" :
                if (check_redirect(target) is not None and 300 <= check_redirect(target) < 400)   :
                    print("[PASS] Port 80 redirect to port 443 ==> Http service redirect to https.")    
                else:
                    print("[WARNING] Your http service is available and does not redirect to https !")
                    print("========> Must close port 80 OR redirect to port 443 -_-")
            elif port["portid"]=="80"  and  port["state"] == "closed":
                print("[PASS] Port 80 is closed ==> No http service .")

            if port["portid"]=="443" and port["state"] == "open" :
                scripts = port["scripts"]
                for s in scripts:
                    if s["name"] == "ssl-enum-ciphers":
                        data=s["data"]
                        if tls_check(data) is True:
                            print("[PASS] Https service support tls ≥ 1.2 ==> No tls 1.0/1.1 ciphers.")
                        else:
                            print("[WARNING] Https supports tls 1.0 or/and tls 1.1 !")
                            print("========> Must reconfigure your https service *_*")
            elif port["portid"]=="443" and  port["state"] =="closed":
                print("[PASS] Https service is not available ==> no tls problems .")

            if port["portid"]=="21" and port["state"] =="open" :
                if not ftp_anon(target):
                    print("[PASS] No ftp anonymous login ==> ftp-anon = 0.")
                else:
                    print("[WARNING] Ftp anonymous login is enabled !")
                    print("========> Must reconfigure ftp settings !")
                    print("- Edit the file  /etc/vsftpd.conf")
                    print("- Set -> anonymous_enable = NO")
            elif port["portid"]=="21" and port["state"] == "closed":
                print("[PASS] Ftp service is disabled ==> No ftp-anon anyway +_+")
        
    except Exception as e:
        print(f"[ERROR] Failed to scan the target :{target}")
        print(f"==>{e}")

        if VERBOSE:
            print(f"{port}")


print("                 $ ******************************************************************* $")
print("                 ------------Welcome to the Regulatory Compilance Scanner 0/------------")
print("\n\n=>This tool scans the hosts to detect some popular service protocols")
print(">This program is based on some rules MUST be deployed in every server for security purposes")
print(">You can check the source code or the tool's documentation for the rules or the scanned services")
print("||")
print(" ==>[DISCLAIMER!] Only use this tool on machines you own or you have permission to scan !")
while 1 :
    print("\n---------------------------------------------------------------------------------")
    print("\n Pls enter a valid host IP to scan(e.g. 127.0.0.1) : \n")
    host_ip = input()
    if validate_ip(host_ip):
        print(f"||Scanning {host_ip} is in progress - VERBOSE=False - press ctrl-c to stop the scan||")
        scan(host_ip)
        print(f"\nhost {host_ip} was scanned successfully :) \n")
    else:
        print("\nInvalid IP format '-' (like cmon bro you even know how to enter a valid IP lmao)")
        print("")
    
