#!/usr/bin/python3.6
# -*- coding: utf-8 -*-


"""
    Get the CPU, memory, uptime or status of an stormshield firewall (tested on
    a SN3000)
    Requirements :
        - python > 3.5, for the subprocess method
        - snmpwalk to send  snmp requests to the host
            CentOS / RedHat : yum install net-snmp-utils
            Debian : apt install snmp
    Usage : python3.6 check_health_stormshield.py -m <mode> <ip destination>


"""

__author__ = 'Devannes Rémi'
__license__ = 'GNU General Public License v3.0'
__version__ = '0.1'
__maintainer__ = 'Devannes Rémi'
__email__ = 'rdevannes88@gmail.com'
__status__ = 'Stand By'

__website__ = "https://redsky.fr/"

import subprocess
import sys
import argparse

#Used to check if the IP is legal
import socket

"""
    Return codes defined by Nagios in the API
    https://assets.nagios.com/downloads/nagioscore/docs/nagioscore/3/en/pluginapi.html
"""

STATUS_OK = 0
STATUS_WARNING = 1
STATUS_CRITICAL = 2
STATUS_UNKNOWN = 3


# Change these id following to your SNMP server configuration
USERNAME = 'username'
AUTH_PASSWORD = 'a_password'
PRIVACY_PASSWORD = 'p_password'

def check_ip(ip):
    """
        Checking if an ip passed to the script is a valid IPv4 one by using the
        socket module
    """
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except:
        raise argparse.ArgumentTypeError("IP isn't a correct IPv4 one")
    return ip


def sendSNMP(ip_dest, oid):
    """
        Send SNMP request by using snmpwalk like a shell command
        Return the whole stdout output in an array if there are no stderr output
    """
    query = subprocess.run(['snmpwalk',
                            #q = quickprint (better for parsing)
                            #v = print only value not the OID
                            '-Oqv',
                            '-v', '3',
                            '-c', 'private',
                            '-u', USERNAME,
                            '-a', 'SHA',
                            '-A', AUTH_PASSWORD,
                            '-x', 'AES',
                            '-X', PRIVACY_PASSWORD,
                            '-l', 'authPriv',
                            ip_dest,
                            oid],
                            stderr=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            universal_newlines=True)

    if not query.stderr == '':
        print("Not receiving any SNMP answer")
        sys.exit(STATUS_CRITICAL)
    else:
        #Split output into an array for each line and delete blank element
        output = query.stdout.split('\n')
        output = [x for x in output if x != '']
        if len(output) == 1:
            output = output[0]
        return output


def check_cpu(ip_dest):
    """
        Print if CPU has encountered an issue

        This OID is proprietary
        https://www.stormshield.com/wp-content/uploads/STORMSHIELD-SYSTEM-MONITOR-MIB.txt
    """

    oid_cpu_health = '1.3.6.1.4.1.11256.1.16.2.1.7'

    cpu_health = sendSNMP(ip_dest, oid_cpu_health)

    """
        Convert list to set to remove double duplicate value, if everything is
        "Good" the list will be empty
    """

    if [x for x in cpu_health if x != '\"Good\"']:
        print("CPU has a problem !")
        sys.exit(STATUS_CRITICAL)
    else:
        print("CPU : OK")
        sys.exit(STATUS_OK)

def check_memory(ip_dest):
    """
        Print the memory used for storage and compute the difference
        to get the percentage of memory used

        http://oidref.com/1.3.6.1.4.1.2021.4.5
        http://oidref.com/1.3.6.1.4.1.2021.4.6
    """

    oid_memTotalReal = "1.3.6.1.4.1.2021.4.5"
    oid_memAvailReal = "1.3.6.1.4.1.2021.4.6"

    memoryTotalReal = sendSNMP(ip_dest, oid_memTotalReal)
    memoryAvailReal = sendSNMP(ip_dest, oid_memAvailReal)

    #Get only number because format is "16661540 kB"
    memoryTotalReal = memoryTotalReal.split(' ')[0]
    memoryAvailReal = memoryAvailReal.split(' ')[0]


    memoryTotalReal = int(memoryTotalReal)
    memoryUsedReal = int(memoryTotalReal) - int(memoryAvailReal)

    memory_ratio = round(memoryUsedReal/memoryTotalReal*100, 3)

    if memory_ratio >= 99.5:
        print('Memory overloaded: ' + str(memory_ratio) + '% used on ' + str(memoryUsedReal) + '/' + str(memoryTotalReal) + " kB")
        sys.exit(STATUS_CRITICAL)
    else:
        print('Memory is OK: ' + str(memory_ratio) + '% used on ' + str(memoryUsedReal) + '/' + str(memoryTotalReal) + " kB")
        sys.exit(STATUS_OK)

def check_uptime(ip_dest):
    """
        Print the uptime
        http://oidref.com/1.3.6.1.2.1.25.1.1
    """
    oid_uptime = "1.3.6.1.2.1.25.1.1"

    uptime = sendSNMP(ip_dest, oid_uptime)

    print("uptime: " + uptime + " (dd:hh:mm:ss)")
    sys.exit(STATUS_OK)

def check_status(ip_dest):
    """
    Print the Global Health
    This OID is proprietary
    https://www.stormshield.com/wp-content/uploads/STORMSHIELD-SYSTEM-MONITOR-MIB.txt
    """

    oid_globalHealth = "1.3.6.1.4.1.11256.1.16.1"

    status = sendSNMP(ip_dest, oid_globalHealth)

    if status != '"Good"':
        print(status)
        sys.exit(STATUS_CRITICAL)
    else:
        print(status)
        sys.exit(STATUS_OK)


def main(args):

    ip_dest = args.ip_dest
    mode = args.mode

    if mode == 'cpu':
        check_cpu(ip_dest)
    elif mode == 'memory':
        check_memory(ip_dest)
    elif mode == 'uptime':
        check_uptime(ip_dest)
    elif mode == 'status':
        check_status(ip_dest)

if __name__ == "__main__":
    # execute only if run as a script
    parser = argparse.ArgumentParser()


    parser.add_argument('-m', '--mode', required=True,
                        type = str.lower,
                        dest = 'mode',
                        choices = ['cpu', 'memory', 'uptime', 'status'],
                        help = 'Health information desired : CPU, memory, uptime or status')

    parser.add_argument(dest = 'ip_dest',
                        metavar = '<ip destination>',
                        type = check_ip,
                        help = "Destination host")

    main(parser.parse_args())
