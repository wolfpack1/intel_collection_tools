"""
Pull sector data on domains. Requires a free license:
http://www1.k9webprotection.com/get-k9-web-protection-free




"""

import os
import socket
import urllib2
import sys
try:
    from urllib.request import urlopen
    from urllib.parse import urlencode,urlparse
    from urllib.error import HTTPError
except ImportError:
    from urllib import urlencode
    from urllib2 import urlopen, HTTPError
    from urlparse import urlparse
import json
import time
import ast
from xml.etree.cElementTree import fromstring



#Example domains
domains_to_process = ['cnn.com','wapacklabs.com','xhampster.com','dow.com']

categoriesUrl = 'http://sitereview.bluecoat.com/rest/categoryList?alpha=true'

# Get one here: http://www1.k9webprotection.com/get-k9-web-protection-free
k9License = 'YOUR K9 LICENSE ID HERE'


def fetchCategories():
	""" --------------------------------------- """
	""" Fetch categories and create local cache """
	""" --------------------------------------- """


	try:
		u = urllib2.build_opener()
		u.addheaders = [('User-agent', 'webcat.py/1.0 (https://blog.rootshell.be)')]
		r = u.open(categoriesUrl)
		data = json.load(r)
		d = dict([('%02x' % c['num'], c['name']) for c in data])
	except urllib2.HTTPError, e:
		sys.stderr.write('Cannot fetch categories, HTTP error: %s\n' % str(e.code))
	except urllib2.URLError, e:
		sys.stderr.write('Cannot fetch categories, URL error: %s\n' % str(e.reason))

	return d


def _chunks(s):
	# Original: https://github.com/allfro/sploitego/blob/master/src/sploitego/webtools/bluecoat.py
	return [s[i:i + 2] for i in range(0, len(s), 2)]


webCats = fetchCategories()

def domain_categorize(url,webCats):
    hostname = url
    port = '80'
    r = urllib2.urlopen('http://sp.cwfservice.net/1/R/%s/K9-00006/0/GET/HTTP/%s/%s///' % (k9License, hostname, port))
    if r.code == 200:       
        e = fromstring(r.read())
        domc = e.find('DomC')
        dirc = e.find('DirC')
        if domc is not None:
            cats = _chunks(domc.text)
            #domain_cat = '%s,%s' % (hostname, [webCats.get(c.lower(), 'Unknown') for c in cats][0])
            domain_cat = '%s' % [webCats.get(c.lower(), 'Unknown') for c in cats][0]
        elif dirc is not None:
            cats = _chunks(dirc.text)
            #domain_cat =  '%s,%s' % (hostname, [webCats.get(c.lower(), 'Unknown') for c in cats][0])
            domain_cat =  '%s' % [webCats.get(c.lower(), 'Unknown') for c in cats][0]
    else:
        print 'Cannot get category for %s\n' % hostname
        domain_cat = '404'
    return domain_cat
	#exit(0)



for domain in domains_to_process:


    try:
        cat_value = domain_categorize(domain,webCats)
    except Exception ,e:
        print e
        print 'exception on  '+domain
        time.sleep(60)
        print 'waiting for a minute and continuing'
        #raise
        continue

    print domain,cat_value

    
