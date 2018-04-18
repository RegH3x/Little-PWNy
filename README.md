### L1ttl3-PWNy

### MiTM PenTester Box
### Rogue AP

This tool enable you to sniff traffic within a LAN offered by an AP. This was tested mainly on a Raspberrip B.

It use different interisting projects for MiTM and networking in general.
* [redsocks](https://github.com/darkk/redsocks)
* [dnsmasq](https://github.com/imp/dnsmasq)
* [hostpad](https://w1.fi/hostapd/)
* [iptables](https://netfilter.org/projects/iptables/index.html)
* [SSLSTRIP+](https://github.com/LeonardoNve/sslstrip2)
* [dns2proxy](https://github.com/LeonardoNve/dns2proxy)


# DEVELOPMENT STATUS - WORK IN PROGRESS


### HTTP/HTTPS Transparent Proxy Working
### SSLSTRIP+ Working

Soon will be ready a first beta


## INSTALL

This configuration was tested on a Raspberri B.

These are the minimum prerequisites (in addition to python 2.7):

`# apt-get install hostapd dnsmasq redsocks iptables iptables-persistent ssh killall`

Python modules

`$ wget https://bootstrap.pypa.io/get-pip.py`

`# python get-pip.py`

`# pip install dnspython twisted pyopenssl`

Enable IP forwarding on machine modifying '/etc/sysctl.conf' and append the key value pair, or uncomment if already present:

	net.ipv4.ip_forward=1

Set name of your machine in '/etc/hosts'
	
	127.0.1.1 little_pwny

Set a name to your machine:

`# hostname little_pwny`

Configure SSH Server modifying '/etc/ssh/sshd_config':

	port=43000
	permitrootlogin no

Configure Services starting at boot:

`# systemctl enable ssh iptables`
`# systemctl disable hostapd dnsmasq redsocks`


## USAGE

Just launch the main script 'attack.py' and follow the wizard:

`# ./attack.py`

WARNING: This was tested on a Raspberrip whcih doesn't have wpa_supplicant shipped. If you have it running you have to kill it and check that your wifi card support AP mode.
`$ iw list | grep -i 'supported interface modes' -A 20 -B 20`


## LEGEND

* NC: NO Certificate Installation on Device Required 	(SSL Bypass)
* NP: NO Proxy Configuration on Device Required 		(Transparent Proxy)
* C: Certificate Installation on Device Required 		(CA SSL Cert Signed)
* LAN PROXY: Proxy that is on same network of AP. It will Intercept and Modify traffic


## SCOPE

**MODE: WIFI AP with LAN PROXY C_NP**
**[HTTP/HTTPS, HTTPS: 2 attacks, TRANSPARENT: Full]**

**MODE: WIFI AP with LAN PROXY NC_NP**
**[HTTP/HTTPS, HTTPS: 1 attacks, TRANSPARENT: Partial]**

### Pro & Cons:

* 100 % Transparent. Completely Transparent HTTP/S Proxy.
* [NC] HTTPS Inspection Enabled (CA self-signed Certificate) + Bypass for failing SSL requests (SSL Pass-Through enabled on Proxy)
* [C]	HTTPS will work only if HSTS or HKPK is not enforced + Bypass for failing SSL requests (SSL Pass-Through enabled on Proxy)
* Dump Traffic in a single point for offline analysis
* Live Traffic Analysis	

* Traffic will Exit from LAN PROXY. So Traffic will flow from devices to AP and from AP to LAN PROXY which will provide external connection.

* [NC] HTTPS will show warnings in Browser and some App will NOT work !
* With HSTS or HKPK it will not work for some Apps and Browser. You will need each certificate for App you want intercept.


**MODE: WIFI AP direct EXT NC_NP**
**[HTTP/HTTPS, HTTPS: 1 attack, TRANSPARENT: Full]**

### Pro & Cons:

* 100 % Transparent. Completely Transparent HTTP/S Proxy.
* You can use this to test weak SSL implementation.
* HSTS Attack: Use of sslstrip2 to bypass HSTS whenever possible. It will try to redirect every https link to http.
* DNS Attack: Use of dns2proxy for correct resolution of changes made by sslstrip2.

* HTTPS will show warnings in Browser and some App will NOT work !
* For now it is not possible to let traffic go through LAN PROXY as HTTPS connection will be initiated by sslstrip on AP. This will be a TODO.
* The traffic will not flow to another machine so you have to put yourself to look at logs for dumps of deciphered traffic (which will be at the end HTTP traffic)


### Extra Features

DNS Resolution on AP othwerwise it will fail. Is necessary a DNS Server on LAN PROXY if you choose to route traffic through LAN PROXY.

1. Redirect DNS calls on attacker machine (LAN PROXY)(DNS Server on LAN PROXY required)
1. DNS Server (those are just examples):
	1.	dnsmasq (linux)
	1.	Nope Proxy (Burp, cross-platform, only java required)
	1.	maradns (windows)
1. DNS Calls exit directly from AP (through a different interface of AP Wifi)


### TO DO:

* Redirect TCP OK

* Redirect UDP :-(
	* Need more details and different tricks to achieve this
		* Redsocks2 [Fork: https://github.com/semigodking/redsocks]
		* Shadowsocks [http://shadowsocks.org/en/download/clients.html]
		
* Dumps Traffic for offline analysis (tshark folder not documented yet)			


### ISSUES [soon I will move it on ISSUES TAB]


* Change 'print' with a logger class for optimizing printing to console
* Clear console screen with maximum portability in mind
* Integrate the script 'show_host_lan.sh' inside 'attack.py' in order to show host connected to AP
	when we choose LAN PROXY, VICTIMS and other parameters
* Check if 'pwny.conf' exist already and if exist ask if we want to load this first
* Invert order of printing for configuration confirmation
* Check location of written logs by all services running
* Order and clean list for 'pwny.conf' to achieve more readibility
* Integrate the full configuration for a standalone little-pwny with Raspberrip B
* Change the 'Popen' calls with fork()
* Add Traffic Dump scripts or instructions
* Add Web Server to have the possibility of hosting different web pages for different domains
* Enforce iptables rules to DENY unwanted traffic (manage ICMP and DROP everything out
* Optimize log dir in 'attack.py'
* Add parameter to 'attack.py' which will select auto mode to auto conf without interaction
* Converet everything to class (maybe next version)

### CONF


### MODE: AP + WIFI (route all traffic coming from WiFi Interface AP trhough LAN PROXY) + HTTPS

DNS Call will be made by your AP or by LAN PROXY.

LAN PROXY:  (e.g. 10.0.10.161: BURP Proxy machine or any other proxy you choose capable of HTTP/HTTPS handling)

	[PROXY_MACHINE] 

	Start Proxy to see traffic - authbind required to open socket on 80/443

	authbind --deep java -jar burp...pro.jar
		
	Burp Listener port 80 (Invisible)	{http-relay}
	Burp Listener port 443 (Invisible)	{http-connect}
	Burp Listener port 5094 (Invisible)	{http-connect}	[GMS]
	Burp Listener port 5228 (Invisible)	 {http-connect}	[mtalk Google]
	Burp Listener port 8080			[OPTIONAL - Management Operations]
				
	Burp Listener port 8085 (UDP - TODO !)
	Burp SSL Pass-Through Enabled (you can choose to disable it but you need to be sure of that, as it will break some HTTPS Connections depending on your configuration).

		
### MODE: AP + WIFI (route all traffic coming from WiFi Interface AP trhough eth or other external interface) + HTTPS

DNS Call wil be made by your AP or by LAN PROXY.

Anyway HTTPS connection will go through AP. So you have to choose another interface where the traffic will flow to external net.


### TRAFFIC DUMP
You can choose to add the protocols as you discover it with tshark or tcpdump on AP. This can be achieved by looking at traffic passing through your AP. Use those filters to see different traffic that you have not seen yet.

* TCP
	* tshark -n -Y "!(tcp.port == 5228 || tcp.port == 5094 || tcp.port == 80 || tcp.port ==443  || tcp.port == 43000 || tcp.port == 8090 || tcp.port == 8091 ||arp || llc || bootp || eapol) and tcp" -i wlan0 -Px

* UDP
	* tshark -n -Y "!(ntp || dns || arp || llc || bootp || eapol) and udp" -i wlan0 -Px
	* QUIC: Google replacement for TCP HTTP
		* udp.port == 80 or udp.port == 443




