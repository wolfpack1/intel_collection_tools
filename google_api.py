"""
Some useful queries using Google API

* need your own app engine ID and API key (free :))

"""

try:
    from urllib.request import urlopen
    from urllib.parse import urlencode,urlparse
    from urllib.error import HTTPError
except ImportError:
    from urllib import urlencode
    from urllib2 import urlopen, HTTPError
    from urlparse import urlparse
import json
import sys
import time
import os


app_eng = ''#Your Google App Engine ID

key = ''#Your Google API key


#query = "Wapack+Labs"# Example query: derive domain based on org name
#query = "inurl:wapacklabs"# Example query: Find URLs with specific string
query = "link:wapacklabs.com"# Example query: Find links for given domain

url = "https://www.googleapis.com/customsearch/v1?key="+key+"&cx="+app_eng+"&q="+query

response_str = urlopen(url)

response_str = response_str.read().decode('utf-8')

response = json.loads(response_str)

try:
    items = response['items']
    for i in items:
        print i['formattedUrl']
except:
    print 'no hits for '+query

    
