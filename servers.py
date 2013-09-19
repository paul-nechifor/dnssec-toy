#!/usr/bin/env python

from subprocess import Popen
import sys, os, time

def start():
    argss = [
        ['ns1.', '2001', 'masterFiles/signed_zone_'],
        ['ns1.ro.', '2002', 'masterFiles/signed_zone_ro'],
        ['ns2.ro.', '2003', 'masterFiles/signed_zone_ro'],
        ['ns1.pers.ro.', '3001', 'masterFiles/signed_zone_pers.ro'],
        ['ns1.com.ro.', '3002', 'masterFiles/signed_zone_com.ro'],
        ['ns1.net.', '2004', 'masterFiles/signed_zone_net']
    ]

    for args in argss:
        a = ['java -jar dist/SI_T45.jar', '--autho'] + args
        params = ['gnome-terminal', '--geometry', '60x24', '--command', " ".join(a)]
        print a
        Popen(params)

def stop():
    os.system("killall gnome-terminal")

time.sleep(0.5)
stop()
start()
