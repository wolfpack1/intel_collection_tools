# -*- coding: utf-8 -*-

"""
"Passive DNS Destoyer" by Chris Hall (christopherhall77@gmail.com)

Passive DNS Destroyer will find ALL available passive DNS intel on;
 - domains
 - IPs
 - CIDR blocks

additional subdomains are automatically identified by searching wildcards for second level domains

Requirements:
- Farsight passive DNS API key with dns.conf file. Example:
  - https://github.com/wolfpack1/whoisrecon/blob/master/dns.conf
- Pygeoip for geolocation
- dnsdbclient.py client. Available here:
    - https://github.com/wolfpack1/whoisrecon/blob/master/dnsdbclient.py
- tld_subdomains.txt for processing TLD subdomains. Available in repo

Usage:
Put domains,IPs, or cidr blocks into text file, then modify the input_file parameter below with the name of the file.
Modify the csv_file_name parameter with the desired name of output file

"""


import re,sys
import socket
import urllib
import sys
from urllib import urlopen, quote
import unicodedata
import codecs
from dnsdbclient import *
from collections import Counter
import time
import datetime
import pygeoip
import csv
import datetime
import time


timestring = time.time()
formatted_timestring = datetime.datetime.fromtimestamp(timestring).strftime('%Y_%m_%d')

input_file = 'indicator_input_file.txt'#input file containing a list of domains, IPs or CIDR blocks
csv_file_name = 'pDNS_output_'+formatted_timestring+'.csv'


gic = pygeoip.GeoIP('GeoIP.dat')

UTF8Writer = codecs.getwriter('utf8')
sys.stdout = UTF8Writer(sys.stdout)

conf = 'dns.conf'
cfg = parse_config(conf)


if cfg.has_key('DNSDB_SERVER'):
    dns_server = cfg['DNSDB_SERVER']

limit = 10000

client = DnsdbClient(dns_server, cfg['APIKEY'],limit = limit, json = True)


def search_is_domain(strg, search=re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", re.I).search):
    return bool(search(strg))

def search_is_IP(strg, search=re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", re.I).search):
    return bool(search(strg))

def search_is_cidr(strg, search=re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}($|/(\d\d))$", re.I).search):
    return bool(search(strg))


##########
## getting all TLDs

tld_source = 'http://www.iana.org/domains/root/db'
page = urllib2.urlopen(tld_source)

data = page.readlines()

single_tlds = []
for line_ in data:
    #print line_
    if '/domains/root/db/' in line_:
        tld = line_.split('/domains/root/db/')[1].split('.html">')[0]
        single_tlds.append(tld)


all_tlds = []
if os.path.exists('tld_subdomains.txt') and os.access('tld_subdomains.txt', os.R_OK):
    f_in = open('tld_subdomains.txt')
    for _line in f_in.readlines():
        _next = _line.strip()
        count_amnt = len(_next.split('.'))
        all_tlds.append([count_amnt,_next])
        
        f_in.close()

all_tlds = list(reversed(sorted(all_tlds)))
for tld in single_tlds:
    all_tlds.append([1,tld])


def get_second_level_domain(indicator):
    for tld_ in all_tlds:
        tld = tld_[1]
        #print 'checking to see if tld:',tld,' is in ',indicator
        if indicator == tld:
            print indicator,' is a TLD , skipping this as a passive DNS input..'
            return ''
        if indicator.endswith('.'+tld):
            subs = indicator[:(-len(tld)-1)]
            las_sub = subs.split('.')[-1]
            second_level = las_sub+'.'+tld
            if second_level != indicator:
                print 'mapping fqdn ',indicator,' to second level ',second_level
            return second_level
        
    print indicator, 'is not a valid domain!!'
    return ''


indicators = []


if os.path.exists(input_file) and os.access(input_file, os.R_OK):
    f_in = open(input_file)
    for _line in f_in.readlines():
        _next = _line.strip()
        if search_is_domain(_next):
            normalized_domain = get_second_level_domain(_next)
            if not normalized_domain == '':
                indicators.append(normalized_domain)
                continue
        if search_is_IP(_next):
            indicators.append(_next)
        if search_is_cidr(_next):
            indicators.append(_next)
            continue
        print _next,' is not a domain, IP, or cidr block. Check your inputs!'
        
f_in.close()

print 'total indicators ', len(indicators)

indicators_to_process = list(set(indicators))
print 'total unique indicators to process ', len(indicators_to_process)



count_row_write = 0

duplicate_tracker = []

#indicators_to_process = ['www.elmercatsocial.cat','104.24.116.131']

with open(csv_file_name, 'wb') as csvfile:
    indicatorwriter = csv.writer(csvfile, delimiter=',',quotechar='"', quoting=csv.QUOTE_MINIMAL)
    indicatorwriter.writerow(['first_seen','last_seen','rrtype','rrname','rdata','cc','count'])
    for indicator in indicators_to_process:
        print 'processing ', indicator
        ### process domain
        if search_is_IP(indicator) or search_is_cidr(indicator):
            all_results = client.query_rdata_ip(indicator)
        if search_is_domain(indicator):
            wild = '*.'+indicator
            all_results = client.query_rrset(wild)
            
        for result in all_results:
            data = json.loads(result)
            data_row = []
            try:
                rrtype = data['rrtype']
            except:
                rrtype = 'na'
            try:
                rec_count = data['count']
            except:
                rec_count = 0
            try:
                rrname = data['rrname']
                if rrname.endswith('.'):
                    rrname = rrname.rstrip('.')
            except:
                rrname = ''

            try:   
                rdata = data['rdata']
            except:
                rdata = ''
            if type(rdata) == list:
                rdata = rdata[0]
            try:
                first_seen_ = data['time_first']
                first_seen = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first_seen_))
            except:
                #print data
                #raise
                #first_seen = 'unk'
                try:
                    first_seen_ = data['zone_time_first']
                    first_seen = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first_seen_))
                except:
                    last_seen = 'unk'
            try:
                last_seen_ = data['time_last']
                last_seen = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_seen_))
            except:
                #print data
                #raise
                #last_seen = 'unk'
                try:
                    last_seen_ = data['zone_time_last']
                    last_seen = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_seen_))
                except:
                    last_seen = 'unk'

            if search_is_IP(rdata):
                try:
                    cc = gic.country_code_by_addr(rdata)
                    #cc = result['country_code']
                except Exception, e:
                    print e
                    #pass
                    cc = '-'
            else:
                cc = '-'
            row_to_insert = [str(first_seen),str(last_seen),str(rrtype),str(rrname),str(rdata),str(cc),str(rec_count)]
            check = ''.join(row_to_insert)
            if check not in duplicate_tracker:
                print row_to_insert
                indicatorwriter.writerow(row_to_insert)
                count_row_write += 1
                

            duplicate_tracker.append(check)


print count_row_write, 'rows written to ',csv_file_name            
