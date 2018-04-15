#!/bin/bash

sudo killall hostapd
sudo killall dnsmasq
sudo killall redsocks
sudo killall dns2proxy
sudo killall sslstrip.py
./clean_iptables.sh

