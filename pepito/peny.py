#!/usr/bin/env python2

import socket
import sys

###############################
############### Client Class ##

class Client:
    def __init__(self, host='127.0.0.1', port='31337'):
        self.host = host
        self.port = port

    def send(self, command):
        cmdString = command[0]
        for e in command[1:]:
            cmdString +=  " " + str(len(e)) + e
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, int(self.port)))
        sock.send(cmdString)
        sock.setblocking(0)
        sock.settimeout(1.0)
        ret = sock.recv(4096)
        while ret != "":
            for l in ret:
                if l != None:
                    sys.stdout.write(l)
            ret = sock.recv(4096)
        sock.close()


    def interactiveMode(self):
        command = '1 '+'x'*1024
        print command
        self.send(command)

    def printUsage(self):
        usage = """Commands (<command number> <parameter> (<parameter> ...)) :
\tChange password :
\t\t0 <old_password> <new_password> (User & Admin)
\tDisplay recipes :
\t\t1 <password> (User & Admin)
\tDisplay stock :
\t\t2 <password> (User & Admin)
\tMake recipe :
\t\t3 <password> <"recipe name"> (Admin only)
\tMake secret recipe :
\t\t4 <password> (Admin only)
\tSell granolas :
\t\t5 <password> <"recipe name"> (User & Admin)
\tBuy ingredients :
\t\t6 <password> <ingredient_name> <amount> (Admin only)
\tMake super secret recipe :
\t\t7 <password> (Admin only)
"""
        print(usage)

###############################

###############################
################ Main Source ##


def main():
    if len(sys.argv) < 3:
        client = Client('127.0.0.7', '31337')
    else:
        client = Client(sys.argv[1], sys.argv[2])

        # print("Usage :\n%s <host IP address> <port>" % sys.argv[0])
        # sys.exit()

    client.interactiveMode()
    # try:
    # except Exception as e:
    #     print(e)

if __name__ == "__main__":
    main()

###############################
