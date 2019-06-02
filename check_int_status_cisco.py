#!/usr/bin/python3.6
# -*- coding: utf-8 -*-


__author__ = 'Devannes Rémi'
__license__ = 'GNU General Public License v3.0'
__version__ = '0.1'
__maintainer__ = 'Devannes Rémi'
__email__ = 'rdevannes88@gmail.com'
__status__ = 'In development'

import subprocess
import sys

"""
    Return codes defined by Nagios in the API
    https://assets.nagios.com/downloads/nagioscore/docs/nagioscore/3/en/pluginapi.html
"""
STATUS_OK = 0
STATUS_WARNING = 1
STATUS_CRITICAL = 2
STATUS_UNKNOWN = 3

USERNAME = 'username'
AUTH_PASSWORD = 'a_password'
PRIVACY_PASSWORD = 'p_password'


def sendSNMP(ip_dest, oid):
    """Send SNMP request by using snmpwalk

    """
    output = subprocess.run(['snmpwalk',
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
    if not output.stderr == '':
        print("Not receiving any SNMP answer")
        sys.exit(STATUS_CRITICAL)
    else:
        return output.stdout

def getInterfaces(ip_dest):
    """Get interfaces with their indexes in an array of tuple
    format (id, intName)

    http://oidref.com/1.3.6.1.2.1.2.2.1.1
    http://cric.grenoble.cnrs.fr/Administrateurs/Outils/MIBS/?oid=1.3.6.1.2.1.2.2.1.1
    """
    interfaces_with_indexes = []
    oid = '1.3.6.1.2.1.2.2.1.2' #OID for interface and name
    snmp_output = sendSNMP(ip_dest, oid)
    liste = snmp_output.split('\n')
    liste.remove('')
    for i in liste:
        temp = i.split(' ')
        interfaces_with_indexes.append((temp[0].split('.')[1], temp[-1]))
    return interfaces_with_indexes

def checkExistingInterface(interfaces, intName):
    """Check if the entered interface name exists
        return his id if she exists
        else it print """
    for i in interfaces:
        if i[1] == intName:
            return i[0]
    return None

def checkStatusInt(interfaceId, ip_dest):
    """ Take an interface ID and check administrative status and operational
        status of a single interface by sending SNMP request to the server
        return both state in a tuple (admin_status, oper_status)

        http://oidref.com/1.3.6.1.2.1.2.2.1.8
        http://cric.grenoble.cnrs.fr/Administrateurs/Outils/MIBS/?oid=1.3.6.1.2.1.2.2.1.8
    """

    #Adding the interface ID to specify it
    oid_admin = '1.3.6.1.2.1.2.2.1.7.' + interfaceId
    oid_oper = '1.3.6.1.2.1.2.2.1.8.' + interfaceId

    """Using split on only keep the state of the interface, answer format is
        IF-MIB::ifOperStatus.15101 = INTEGER: down(2)
        IF-MIB::ifAdminStatus.15101 = INTEGER: down(2)
        """
    admin_status = sendSNMP(ip_dest, oid_admin).split(' ')[-1]
    oper_status = sendSNMP(ip_dest, oid_oper).split(' ')[-1]

    return (admin_status, oper_status)

def main():
    #Check if all arguments are passed
    if len(sys.argv) < 2:
        print("Missing 2 arguments in the command !")
        sys.exit(STATUS_UNKNOWN)
    elif len(sys.argv) < 3:
        print("Missing 1 argument in the command !")
        sys.exit(STATUS_UNKNOWN)
    else:
        ip_dest = sys.argv[1]
        intName = sys.argv[2]

        interfaces_list = getInterfaces(ip_dest)
        interface = checkExistingInterface(interfaces_list, intName)

        #Check if an interface has this name
        if interface is None:
            print("The interface " + intName + " doesn't exist, set exact name, case sensitive")
            sys.exit(STATUS_CRITICAL)

        admin_status, oper_status = checkStatusInt(interface, ip_dest)
        print(repr(admin_status))
        print(repr(oper_status))
        if admin_status == 'down(2)':
            print("Interface administrativement down")
            sys.exit(STATUS_WARNING)
        elif admin_status == 'testing(3)':
            print("Interface en etat de test")
            sys.exit(STATUS_CRITICAL)
        elif admin_status == 'up(1)':
            if oper_status == 'up(1)':
                print("Interface " + intName + " is up !")
                sys.exit(STATUS_OK)
            elif oper_status == 'down(2)':
                print("Interface "  + intName + " is down !")
                sys.exit(STATUS_CRITICAL)
            elif oper_status == 'testing(3)':
                print("Interface " + intName + " is in testing")
                sys.exit(STATUS_CRITICAL)
            elif oper_status == 'unknown(4)':
                print("Interface " + intName + " is in unknown state")
                sys.exit(STATUS_CRITICAL)
            elif oper_status == 'dormant(5)':
                print("Interface " + intName + " is waiting for external actions")
                sys.exit(STATUS_CRITICAL)
            elif oper_status == 'notPresent(6)':
                print("Interface " + intName + " is not present")
                sys.exit(STATUS_CRITICAL)
            else:
                print("Interface " + intName + " has an unknown issue")
                sys.exit(STATUS_CRITICAL)

if __name__ == "__main__":
    # execute only if run as a script
    main()
