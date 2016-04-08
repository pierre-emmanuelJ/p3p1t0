#!/usr/bin/env python2

'''
Pepito client light
'''

from sys import stdin, stdout, exit
from socket import socket, AF_INET, SOCK_STREAM
from argparse import ArgumentParser


###############################
############### Client Class ##

class Client(object):
    '''
    Pepito client class
    '''
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def send(self, command):
        '''
        send command to pepito server
        '''
        cmd_string = command[0]
        for e in command[1:]:
            cmd_string +=  " " + str(len(e)) + e
        print cmd_string
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((self.host, int(self.port)))
        sock.send(cmd_string)
        sock.setblocking(0)
        sock.settimeout(1.0)
        ret = sock.recv(4096)
        while ret != "":
            for l in ret:
                if l != None:
                    stdout.write(l)
            ret = sock.recv(4096)
        sock.close()

    def interactive_mode(self):
        '''
         interactive shell
        '''
        stop = 0
        while stop == 0:
            stdout.write("pepitoCLI>")
            line = stdin.readline()
            if line == "":
                stop = 1
                print "  \nBye."
            elif line != "\n":
                command = line.strip('\n').split('"')
                if command.count(""):
                    command.remove("")
                if len(command) > 1:
                    last = command[-1]
                    tmp = [c.split(" ") for c in command[:-1] if c != ""]
                    command = []
                    for c in tmp:
                        command.extend(c)
                    command.append(last)
                    if command.count(""):
                        command.remove("")
                else:
                    command = command[0]
                    command = line.strip("\n").split(" ")
                if command[0] == "help":
                    self.print_usage()
                else:
                    print command
                    self.send(command)

    @classmethod
    def print_usage(cls):
        '''
        usage for interacting wiht the server
        '''
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
"""
        print usage

###############################

###############################
################ Main Source ##


def main():
    '''
    main routine
    '''
    parser = ArgumentParser(description='Pepito lightened client')
    parser.add_argument('-H', '--host', type=str, default="127.0.0.1",
                        dest="host")
    parser.add_argument('-p', '--port', type=int, default=31337, dest="port")
    args = parser.parse_args()
    try:
        client = Client(args.host, args.port)
        client.interactive_mode()
    except Exception as e:
        print e

if __name__ == "__main__":
    main()

###############################
