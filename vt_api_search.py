"""
Examples of various queries using VT private API - hashes printed to screen


"""

import re,sys
import json
import urllib
import urllib2
import requests
import time
from datetime import date, timedelta
import os

vt_api_key = ''#your VT key, script no worky without


#q = "type:email positives:1+ fs:2017-03-19+"#find malicious email files
#q = "positives:1+ fs:"+currentdate+"""- ahnlab-v3 :"Win-Trojan/Xema.variant" """#AV detection search
#q = 'similar-to:102427bfffd95a4c00badf331a3e7fe7ec75758306bcfef9f3e55ac8dd1ca9ee'#find similar files
#q = "engines:poison"#AV common name search

try:
    print q
except:
    print 'uncomment one of the above searches to test out script!'
    exit()

def VT_query(query,offset):
    results = []
    result_master = []

    try:
        int(offset)
        #print 'no offset...'
        params = {'apikey': vt_api_key, 'query': query}
    except:

        params = {'apikey': vt_api_key, 'query': query, 'offset':offset}



    #print params        
    response = requests.get('http://www.virustotal.com/vtapi/v2/file/search', params=params, verify=False)
    #print response
    response_result = str(response)
    #print response_result
    if response_result == '<Response [204]>':
        return '204'

    if not response_result == '<Response [204]>':
        try:
            json_response = response.json()
            
            #print json_response
            test = json_response["hashes"]
            for hashes in test:
                results.append(hashes)
            #print test[-1]
            try:
                offset = json_response["offset"]
                result_master.append(results)
                result_master.append(offset)
                result_master.append('offset_check')
                return result_master
                
            except:
                print 'last page..'
                return results

        except:
            raise


all_hashes = []

result_page_counter = 0

print 'processing '+q
offset = 1     
results = VT_query(q,offset)

while offset == 1:
    if results is None:
        break

    #print results[1]
    if len(results) == 3 and results[2] == 'offset_check':
        result_page_counter += 1
        hashes = results[0]
        offset = results[1]
        results = VT_query(q,offset)
        #print str(len(hashes))+' for offset '+offset[:10]
        print 'processing page ',result_page_counter,'of results ..'
        offset = 1
        for samp in hashes:                
            #print samp
            all_hashes.append(samp)

    else:
        #print 'downloading first or last page..'
        offset = 0
        hashes = results[0]

        if len(hashes[0]) == 1:
            all_hashes.append(hashes)

                
        else:
            for samp in hashes:
         
                all_hashes.append(samp)

print 'total samples found ', len(all_hashes)

for hash_ in all_hashes:
    print hash_

    
