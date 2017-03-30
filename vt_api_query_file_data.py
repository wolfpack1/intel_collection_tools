
"""
Takes an input file of hashes and searches against Virus Total. results written to CSV. modify file_info parameter to specify desired fields


"""


import re,sys
import json
import urllib
import urllib2
import requests
import time
import os
import csv


csv_file_name = 'my_output_file.csv'#output file to write results                        
file_with_hashes = 'my_input_file.txt' #file with hashes to search
#items that you want written to CSV, see fields below
file_info = ["sha256","first_seen","last_seen","positives","type","submission_names","ITW_urls","times_submitted"]

api_key = ''#must put in your API key!!

"""
Available fields returned by VT API:

vhash
submission_names
scan_date
first_seen
total
additional_info
size
scan_id
times_submitted
harmless_votes
verbose_msg
sha256
type
scans
tags
unique_sources
positives
ssdeep
md5
permalink
sha1
resource
response_code
community_reputation
malicious_votes
ITW_urls
last_seen

"""

hashes = []

if os.path.exists(file_with_hashes) and os.access(file_with_hashes, os.R_OK):
    f_in = open(file_with_hashes)
    for _line in f_in.readlines():
        hashes.append(_line)

print 'unique files ', len(list(set(hashes)))

               
def query_VT_specific(md5):
        results = []
        pos_scan = []
        params = {'apikey': api_key, 'resource': md5,'allinfo': 1}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, verify=False)
        json_response = response.json()
        try:
            for type_ in file_info:
                value = json_response[type_] 
                results.append([type_,value])
            return results
        except:
            print json_response


counter_ = 0
    
with open(csv_file_name, 'wb') as csvfile:
        
    indicatorwriter = csv.writer(csvfile, delimiter=',',quotechar='"', quoting=csv.QUOTE_MINIMAL)        

    indicatorwriter.writerow(file_info)

    print 'counter ,'
    counter_ += 1
    print counter_

    for md5_ in hashes:

        #md5 = md5_[1]
        #rulename = md5_[0]
        print 'Querying API for data on file '+md5_

        results = query_VT_specific(md5_)

        if results is None:
            print 'exception on ',md5_
            #raise
            continue
        row_data = []
        for r in results:
            row_data.append(r[1])
        #row_data.append(rulename)
        print row_data
        print '________________________________________________'
        indicatorwriter.writerow(row_data)

                


                
