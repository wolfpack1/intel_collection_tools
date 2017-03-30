"""
Takes input file of hashes and finds any associated network-indicators using VT API


"""


import re,sys
import json
import urllib
import urllib2
import requests
import time
import os
import csv


hash_list = 'hash_list.txt'#flat file with list of hashes
csv_file_name = 'csv_output_file.csv'#output file name
api_key = ''#VT API key


def search_is_domain(strg, search=re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", re.I).search):
    return bool(search(strg))

def search_is_bogon(strg, search=re.compile(r"^(^127\.0)|(^192\.168)|(^10\.)|(^172\.1[6-9])|(^172\.2[0-9])|(^172\.3[0-1])$", re.I).search):
    return bool(search(strg))

def search_is_IP(strg, search=re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", re.I).search):
    return bool(search(strg))




hashes = []

if os.path.exists(hash_list) and os.access(hash_list, os.R_OK):
    f_in = open(hash_list)
    for _line in f_in.readlines():
        #print _next
        _next = _line.strip()
        _next = _next.split('#', 1)[0]
        hashes.append(_next)

def query_VT(md5):
                params = {'apikey': api_key, 'hash': md5}
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/behaviour', params=params, verify=False)
                json_response = response.json()
                #print json_response
                payload = []
                try:
                    test = json_response["network"]
                    #print test
                    if test.has_key('http') and len(test['http']) != 0:
                                    all_http = test['http']
                                    payload.append(all_http)
                                
                    if test.has_key('dns') and len(test['dns']) != 0:
                                    all_dns =  test['dns']
                                    payload.append(all_dns)
                                
                    if test.has_key('tcp') and len(test['tcp']) != 0:
                                    all_tcp = test['tcp']
                                    payload.append(all_tcp)

                    if test.has_key('udp') and len(test['udp']) != 0:
                                    all_udp = test['udp']
                                    payload.append(all_udp)
                    if test.has_key('hosts') and len(test['hosts']) != 0:
                                    all_hosts = test['hosts']
                                    #print all_hosts
                                    payload.append(all_hosts)

                    return payload
                                

                except KeyError:
                    pass


def process_network(payload):
    dns_proc = []
    http_proc = []
    tcp_proc = []
    hosts = []

    for results in payload:    

        for item in results:
            print item
            try:
                            uri = item['uri']
                            http_proc.append('uri,'+uri)
            except KeyError:
                            pass
            try:
                            user_agent = item['user-agent']
                            http_proc.append('user_agent,'+user_agent)
            except KeyError:
                            pass
            try:
                            host = item['host']
                            http_proc.append('host,'+host)

            except KeyError:
                            pass
            try:
                            port = item['port']
                            port = str(port)
                            http_proc.append('port,'+port)

            except KeyError:
                            pass
            try:
                            port = item['dport']
                            port = str(port)
                            http_proc.append('dport,'+port)

            except KeyError:
                            pass

            try:
                            hostname = item['hostname']
                            dns_proc.append(hostname)
            except KeyError:
                            pass
            try:
                            ipsrc = item['src']
                            ipdst = item['dst']
                            tcp_proc.append('dst,'+ipdst)
            except KeyError:
                            pass
                        
            try:
                            ip = item['ip']
                            if search_is_IP(str(ip)):
                                tcp_proc.append('ip,'+ip)
            except KeyError:
                            pass

        newlist = []
        if len(dns_proc) != 0:
    
            for item in dns_proc:
                try:
                    itemstr = str(item)
                    if itemstr != 'VBOXSVR.ovh.net':
                        stripped = ''.join(itemstr.split('.ovh.net')[:1])
                        if search_is_domain(stripped):
                            newlist.append('hostname,'+stripped)
                except UnicodeEncodeError:
                    newlist.append('hostname,'+item)                                        
            newlist = list(set(newlist))
        newtcplist = []
        if len(tcp_proc) != 0:
            for item in tcp_proc:
                if not search_is_bogon(item):
                    newtcplist.append(item)
            newtcplist = list(set(newtcplist))

                                            
        master_network_list = list(set(newtcplist + newlist + http_proc +hosts))
        return master_network_list

with open(csv_file_name, 'wb') as csvfile:
    print 'writing all results to '+csv_file_name
        
    indicatorwriter = csv.writer(csvfile, delimiter=',',quotechar='"', quoting=csv.QUOTE_MINIMAL)        
    indicatorwriter.writerow(['FILE_HASH','NETWORK_TYPE','NETWORK_VALUE'])       
                            

    for md5 in hashes:
        print 'processing '+md5
        
        try:
            payload = query_VT(md5)
            
        except:
            print 'exception on '+ md5
            continue
        if payload is None:
            continue
        c2s = process_network(payload)
        try:
            c2s = process_network(payload)
        except TypeError:
            c2s = ''
        for item in c2s:
            item = item.split(',')
            network_type = item[0]
            network_value = item[1]
            #print md5+','+str(item)
            indicatorwriter.writerow([md5,network_type,network_value])    
        


                
