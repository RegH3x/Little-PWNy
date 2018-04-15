#!/bin/bash

echo -e "\nIPTABLES RULES:\n"
sudo iptables-save

echo -e "\nProcesses Running:\n"
sudo ps -ef | grep -v grep | egrep 'hostapd|dnsmasq|redsocks|dns2proxy|sslstrip|sslsniff|bettercap|beef'

