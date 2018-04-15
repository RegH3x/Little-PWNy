#!/usr/bin/python
# -*- coding: utf-8 -*-

import re

# Filtro HTTP Domini e IP contattati
reg_connect = re.compile('CONNECT\s(.*)\sHTTP/1.1')

# Filtro DNS Domini ricercati
reg_dns = re.compile('\s([\w\-.]*)"$')


def http(line): return reg_connect.findall(line)

def dns(line): return reg_dns.findall(line)


def main():


    # Scelta Protocollo
    print '''
        1. HTTP
        2. DNS
    '''
    choice = 0
    
    try:
        choice = input('Scegli il parser del protocollo (1,2): ')
    
    except:
        
        print 'Wrong Choice';exit(1)
    
    if choice < 1 or choice > 2: print 'wrong choice';exit(1)
    
    
    # Scelta File INPUT
    try:
        
        handle_name = raw_input('Nome File dove è contenuto il dato generato da tshark in CSV: ')
    
    except:
    
        print 'Wrong Choice';exit(1)

    if handle_name is None or handle_name == '': print 'Non hai inserito una sega';exit(1)
        

    # Estrapoliamo i domini dal CSV generato da Wireshark
    domains = []
    with open(handle_name,'r') as wirecsv:

        for line in wirecsv:

            if choice == 1: res = http(line)
            if choice == 2: res = dns(line)

            if len(res) == 1: domains.append(res[0])

    # Eliminiamo i doppioni ed ordiniamo la lista
    domains = sorted(set(domains))

    # Mostriamo a schermo e Scriviamo nel file di output i dati  estrapolati
    print '\n'
    hOut = open('out/out_'+handle_name,'w')

    for line in domains:
        print line
        hOut.write(line+'\n')
    
    print '\n'
    hOut.close()
 


if __name__ == '__main__': main()

