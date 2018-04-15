#!/bin/bash


# Protocol to dump file
PROTO=$1

# Victim IP Address
VICTIM=$2

# Folder where to store Dumps
DEST_DUMP=$3


echo -e "\n\t*-*-*- DUMPER AP NETWORK -*-*-*"
echo -e "\n"
echo -e '\tUsage: ./tshark_filters.sh <PROTOCOL_TO_DUMP> <VICTIM_IP>\n'

echo -e '\tPROTOCOL_TO_DUMP:\n\t\tHTTP\n\t\tDNS\n\t\tOTHER\n'

echo -e '\tVICTIM_IP: e.g. 10.0.10.x IP of VICTIM\n'

echo -e "\tOutput Dir: $DEST_DUMP"


if [ -z $PROTO ]
	then
		echo 'Inserisci il Protocollo'
		exit 1
fi

if [ -z $VICTIM ]
	then
		echo 'Inserisci IP vittima'
		exit 1
fi

if [ -z $DEST_DUMP ]
        then
                echo 'Inserisci Cartella Destinazione Output'
                exit 1
fi


if [[ ($PROTO == 'http') || ($PROTO == 'HTTP') ]]
	then
		nohup tshark -i wlan0 -n -Y "ip.addr == $VICTIM and http" -T fields -e _ws.col.Info  -E header=y -E separator=, -E quote=d -E occurrence=f > "$DEST_DUMP"/http &
fi

if [[ ($PROTO == 'dns') || ($PROTO == 'DNS') ]]
	then
		#nohup tshark -i wlan0 -n -Y "ip.addr == $VICTIM and dns" -T fields -e _ws.col.Info  -E header=y -E separator=, -E quote=d -E occurrence=f > "$DEST_DUMP"/dns &
		echo -e "\nEnter password for read dns logs\n"
		sudo cat /var/log/dnsmasq.log | grep query | grep $VICTIM | sed s/$VICTIM//g > "$DEST_DUMP"/dns
fi

if [[ ($PROTO == 'other') || ($PROTO == 'OTHER') ]]
	then
		nohup tshark -i wlan0 -n -Y "ip.addr == $VICTIM and not tcp.port == 8080 and not dns" -T fields -e frame.time -e eth.src -e eth.dst -e ip.src -e ip.dst -e ip.proto -e _ws.col.Info  -E header=y -E separator=, -E quote=d -E occurrence=f > "$DEST_DUMP"/other &
fi

echo -e "\n"
echo -e "[*] Process Started Succesfully!\n"
echo -e "[*] PID tshark DUMP $PROTO of $VICTIM: $!\n"
echo -e "[*] To kill use 'sudo kill $!'\n"

echo -e "\n[*] In case of DNS the output is already written in $DEST_DUMP/dns"
echo -e "[*] No process running for DNS\n"

exit 0

