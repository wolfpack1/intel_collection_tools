"""
Example for polling Virus Total RSS feed and downloading hits


"""

import re,sys
import json
import urllib
import urllib2
import requests
import feedparser
import time
import os



api_key = ''#Your VT key

file_path = "E:\\malware_download_path\\"#file path where you want to download your VT Yara hits
rule_set = 'notifications'#name of your rulest on VT
interval = 1800#interval to poll VT feed

def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""



def query_VT_specific(md5):
                pos_scan = []
                params = {'apikey': api_key, 'resource': md5,'allinfo': 1}
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                json_response = response.json()
                #print json_response

                return json_response

                #print json_response["ITW_urls"][0] #replace "key value" with desired field         
        

while True:

    print '-----------------------------------------'

    
    already_downloaded = os.listdir(file_path)
    
    
    d = feedparser.parse('https://www.virustotal.com/intelligence/hunting/notifications-feed/?key='+api_key+'&output=xml')

    for post in d.entries:

        
        description = (post.description)

        md5 = find_between( description, "md5: ", "<br />" )
        rule = find_between( description, "rule:", "<br />" )
        ruleset = find_between( description, "ruleset:", "<br />" )


        actual_filename = rule+'_'+md5


        
        if actual_filename not in already_downloaded:
            if rule_set in ruleset:
                params = {'apikey': api_key , 'hash': md5}
                try:
                    response = requests.get('https://www.virustotal.com/vtapi/v2/file/download', params=params,verify=False)
                    downloaded_file = response.content
                    f = open(file_path+actual_filename, 'wb')
                    f.write(downloaded_file)
                    f.close()
                    print 'downloading '+md5
                except:
                    print 'except on '+md5
                    continue
    print 'sleeping for a bit, zzzzz'
    time.sleep(interval)


    





        

                

