# -*- coding: utf-8 -*-
"""
Use Domain Tools API to find all domains (currently registered and previously registered) with keyword
Useful for finding typoquats & brand-jackers
*need Domain Tools username and API key

"""


import os
import urllib
import urllib2
from urllib import urlopen, quote

import json
import sys
import time
import os

csv_file_name = 'radiance_domaintools_hits1.csv'
api_key = ''#API key
username = ''#API username

terms = ['wheaten']#your keyword(s)


print 'total terms ', len(list(set(terms)))

for t in terms:
    pagination = 1
    page_num = 1
    all_domains_ = []
    while pagination == 1:

        #print 'processing page ', page_num
        #print 'trying ..',d
        results = []
        elements = []

        retry = 0

        while retry == 0:

            extra = 5
            url = "http://api.domaintools.com/v2/domain-search/?query="+t+"&api_username="+username+"&api_key="+api_key+"&page="+str(page_num)
            try:
                file = urllib2.urlopen(url)
                retry = 1
            except:
                time.sleep(55+extra)
                continue

        data = file.read()

        data = json.loads(data)

        page_test = data['response']['query_info']['page']
        print 'debug page ', page_test

        domains_ = []
        for d in data['response']['results']:

            domain_name = d['sld']
            tlds = d['hashad_tlds']
            #print domain_name
            #print tlds:
            for tld in tlds:
                fqdn = domain_name+'.'+tld
                domains_.append(fqdn)
                all_domains_.append(fqdn)
                print fqdn
        if len(domains_) == 0:
            pagination = 0
            #print 'pagination done!!!! '

        #print 'total domains ', len(domains_)
        page_num += 1

    print 'total domains found:', len(all_domains_)
    print 'total pages:', page_num
    pagination = 1
    page_num = 1
      


