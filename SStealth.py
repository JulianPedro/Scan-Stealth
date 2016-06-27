#!/usr/bin/python
# -*- coding: utf-8 -*-
#Sudo
#Python3
#Install scapy
import os
import sys
import time
import datetime
import optparse
import socket
from scapy.layers.inet import *
from scapy.all import *
#Banner
os.system("clear")
print("|-------------------------|")
time.sleep(0.2)
print("|-------ScanStealth-------|")
time.sleep(0.2)
print("|-------------------------|")
time.sleep(0.2)
print("|-------------------------|")
time.sleep(0.2)
print("|By: Julian Pedro F. Braga|")
time.sleep(0.2)
print("|-------------------------|")
print('\n')
time.sleep(0.2)
#Banner
tosee = os.path.exists("/bin/scapy")
if tosee == True:
    if sys.argv[1:] == []:
        print("")
        print("Usage: sudo SStealth [options] [HOST]")
        print("""
        -c [Number] packet count
        -o          Identify System
        -p [PORT]   Port Scan
        -t          Top Ports
            """)
    else:
        parser = optparse.OptionParser()
        parser.add_option("-c", "--c", dest="nbp", action="append", help="Number Packet Count", metavar="Ex:1")
        parser.add_option("-o", "--o", dest="sys", action="store_const", help="Identify System", metavar="IDS")
        parser.add_option("-p", "--p", dest="ps", action="append", help="Port", metavar="Ex:80")
        parser.add_option("-t", "--top-ports", dest="pts", action="store", help="Top Ports", metavar="Top Ports")
        (options, args) = parser.parse_args()

        def Ping():
            host = (sys.argv[-1])
            p = ''.join(options.nbp)
            print("*"*60)
            os.system("ping -c"+p+" "+host+"")
            print("*"*60)
            print('\n')

        def PortScan():
            if int(''.join(options.ps)) >= 1 and int(''.join(options.ps)) <= 65535:
                host = (sys.argv[-1])
                port = int(''.join(options.ps))
                so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                so.settimeout(0.5)
                code = so.connect_ex((host, port))
                so.close()
                if code == 0:
                    print("*" * 60)
                    print("[+] Port %i Open"%(port))
                    print("*" * 60)
                    print('\n')
                else:
                    print("*" * 60)
                    print("[-] Port %i Closed"%(port))
                    print("*" * 60)
                    print('\n')
            else:
                print("*" * 60)
                print("Port Invalid!")
                print("*" * 60)
                print('\n')

        def TopPorts():
                host = (sys.argv[-1])
                port = [21, 22, 25, 53, 80, 110, 135, 137, 138, 139, 143, 443, 465, 587, 995, 1521, 2525, 3306, 8000, 8080]
                for i in port:
                    so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    so.settimeout(0.5)
                    code = so.connect_ex((host, i))
                    so.close()
                    if code == 0:
                        print("[+] Port %i Open"%(i))
                    else:
                        print("[-] Port %i Closed"%(i))
                print('\n')

        def System():
            try:
                host = (sys.argv[-1])
                ip = IP()
                ping = ICMP()
                ip.dst = host
                resp = sr1(ip/ping)
                res = sr1(ARP(pdst=sys.argv[2]))
                mac = res.hwsrc
                if resp.ttl == 255:
                    print('\n')
                    print("*" * 60)
                    print("[+] System Unix")
                    print("*" * 60)
                    print('\n')
                elif resp.ttl == 64:
                    print('\n')
                    print("*" * 60)
                    print("[+] System Linux")
                    print("*" * 60)
                    print('\n')
                elif resp.ttl == 128:
                    print('\n')
                    print("*" * 60)
                    print("[+] System Windows")
                    print("*" * 60)
                    print('\n')
                else:
                    print('\n')
                    print("*" * 60)
                    print("[-] Unknown System ")
                    print("*" * 60)
                    print('\n')
            except:
                print('\n')
                print("*" * 60)
                print("[ WARNING ] The function requires administrative privileges.")
                print("*" * 60)
                print('\n')

        if options.pts:
            TopPorts()

        elif options.nbp:
            Ping()

        elif options.ps:
            PortScan()

        elif options.sys == None:
            System()

else:
    print('\n')
    print("*" * 60)
    print("[-]Scapy Not Installed")
    print("*" * 60)
    print('\n')
    os.system("apt-get install scapy")