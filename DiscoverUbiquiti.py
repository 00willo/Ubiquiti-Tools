#!C:\Users\willo\OneDrive\Documents\Ubiquiti-Tools\.venv\Scripts\python

# usr/bin/env python

# -------------------------------------------------------------------------------
#  "THE BEER-WARE LICENSE" (Revision 42):
#  <patrick@kerwood.dk> wrote this script. As long as you retain this notice you
#  can do whatever you want with this stuff. If we meet some day, and you think
#  this stuff is worth it, you can buy me a beer in return.
#
#     - Patrick Kerwood @ LinuxBloggen.dk
# -------------------------------------------------------------------------------
# Modified by Graham Williamson

import argparse
import paramiko
import re
import subprocess

from datetime import datetime
from scapy.all import srp,Ether,ARP,conf

usw_flex_mini_mac_prefix = [
    "74:ac:b9",
]
uap_ac_iw_mac_prefix = [
    "78:45:58",
]
us_16_150w_mac_prefix = [
    "68:d7:9a",
]

macs_prefix = [
    "f0:9f:c2",
    "44:d9:e7",
    "04:18:d6",
    "80:2a:a8",
    "00:15:6d",
    "24:a4:3c",
    "dc:9f:db",
    "68:72:51",
    "00:27:22",
    "fc:ec:da",
    "74:83:c2",
    "18:e8:29",
    "78:8a:20",
    "b4:fb:e4",
]

macs = (
    macs_prefix
    + usw_flex_mini_mac_prefix
    + uap_ac_iw_mac_prefix
    + us_16_150w_mac_prefix
)


class bcolors:
    OKGREEN = "\033[92m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    HEADER = "\033[93m"


def arp_scan(ips):
    start_time = datetime.now()
    results = []
    conf.verb = 0
    eth_broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_frame = ARP(pdst = ips)
    ans, unans = srp(eth_broadcast_frame/arp_frame,
             timeout = 2,
             #iface = interface,
             inter = 0.1)

    for _,rcv in ans:
        ip = rcv[1].psrc
        mac = rcv[1].hwsrc
        results.append((ip, mac))
    return results

def print_ubnt(arp_results):
    print()
    print("Ubiquiti Devices\n")
    #import ipdb;ipdb.set_trace()

    FORMAT = "%-16s %-18s %-16s %-18s %-12s %-45s"
    print(FORMAT % ("IP", "MAC", "Model", "Hostname", "Version", "Status"))

    colorcount = 1

    for device in arp_results:
        bool = False

        for mac in macs:
            if mac in device[1]:
                bool = True

        if bool:
            ip = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", device, re.I).group()
            mac = re.search(r"([0-9A-F]{2}[:-]){5}([0-9A-F]{2})", device, re.I).group()
            model = ""
            version = ""
            hostname = ""
            status = ""

            try:
                client = paramiko.SSHClient()
                client.load_system_host_keys()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    ip, username=sshname, password=sshpass, allow_agent=False
                )
                stdin, stdout, stderr = client.exec_command(
                    "mca-cli <<EOF\ninfo\nquit\nEOF"
                )

                if stdout.channel.recv_exit_status() == 0:
                    for line in stdout:
                        if "Model" in line:
                            model = line.rsplit(None, 1)[-1]
                        elif "Version" in line:
                            version = line.rsplit(None, 1)[-1]
                        elif "Hostname" in line:
                            hostname = line.rsplit(None, 1)[-1]
                        elif "Status" in line or "Inform" in line:
                            status = (
                                line.rsplit(None, 2)[-2]
                                + " "
                                + line.rsplit(None, 1)[-1]
                            )

                        if hostname == "":
                            stdin, stdout, stderr = client.exec_command("uname -a")
                            for line in stdout:
                                hostname = line.split(None, 2)[1]

                else:
                    stdin, stdout, stderr = client.exec_command("uname -a")
                    for line in stdout:
                        hostname = line.split(None, 2)[1]

                    stdin, stdout, stderr = client.exec_command("cat /etc/version")
                    for line in stdout:
                        version = line.strip("\n")

                    stdin, stdout, stderr = client.exec_command("cat /etc/board.info")
                    for line in stdout:
                        if "board.name" in line:
                            model = line.rsplit("=", 1)[-1].strip("\n")

                client.close()
            except paramiko.AuthenticationException:
                status = "%sAuthentication failed!%s" % (bcolors.FAIL, bcolors.ENDC)
            except:
                status = "%sError trying to connect!%s" % (bcolors.FAIL, bcolors.ENDC)

            if colorcount % 2 == 0:
                print(FORMAT % (ip, mac, model, hostname, version, status))
            else:
                colorFormat = bcolors.HEADER + FORMAT + bcolors.ENDC
                print(colorFormat % (ip, mac, model, hostname, version, status))

            colorcount += 1


parser = argparse.ArgumentParser()
parser.add_argument(
    "-n", "--network", required=True, help="Make a ping sweep on subnet Eg. -n 10.0.0.0/24"
)
parser.add_argument(
    "-c",
    "--connect",
    help="Specify the SSH username",
    default=False,
    action="store_true",
)
parser.add_argument("-u", "--user", help="Specify the SSH username", default="ubnt")
parser.add_argument("-p", "--password", help="Specify the SSH paswword", default="ubnt")
args = parser.parse_args()

print("Processing args")
if args.network:
    #ping_sweep(args.network)
    print("Conducting arp scan")
    arps = arp_scan(args.network)

if args.connect:
    sshname = args.user
    sshpass = args.password

print_ubnt(arps)
print()
