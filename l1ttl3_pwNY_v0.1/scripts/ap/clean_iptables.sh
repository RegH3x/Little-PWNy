#!/bin/bash

echo 'Cleaning NAT table and restore default iptables table'

sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t nat -Z
sleep 2
sudo iptables-restore /home/tony/Little-PWNy/l1ttl3_pwNY_v0.1/redsocks/rules.orig.v4
