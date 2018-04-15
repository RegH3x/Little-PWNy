#!/bin/bash

# Read /etc/sysctl.conf and see for ipv4.redirect if it is enabled

# Enable Interface AP wlan0
# External Net are on eth0
sudo ip link set wlan0 up

sleep 5

# Start AP at wlan0
sudo hostapd -e /dev/urandom -B /etc/hostapd/hostapd.conf 2> /dev/null

sleep 5

# Set IP AP at wlan0
sudo ip addr add 10.0.10.1/24 dev wlan0

sleep 10

# Start DNS & DHCP Server
sudo dnsmasq -C /etc/dnsmasq.conf

# IF Traffic go out from Little Pwny
# Forward and Source NAT from wlan0 to eth0
#sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
#sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
