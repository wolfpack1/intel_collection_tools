"""
Example for using Namecheap's free API to check domain availability.
You need your own Namecheap API key & account. Domains_to_check string contains examples

"""


import urllib2
import StringIO



api_key = ''#your namecheap key

user_name = ''#your namecheap username
client_ip = ''#your ip

domains_to_check = 'wpaasdf.com,ddddddddddddddcc.com,wapacklabs.com'#add domains to check comma separated list


def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""


url = 'https://api.namecheap.com/xml.response?ApiUser='+user_name+'&ApiKey='+api_key+'56b4c87ef4fd49cb96d915c0db68194&UserName='+user_name+'&Command=namecheap.domains.check&ClientIp='+client_ip+'&DomainList='+domains_to_check

response = urllib2.urlopen(url)
data = response.read()
buf = StringIO.StringIO(data)
for line in buf:
    if '<DomainCheckResult Domain=' in line:

        first = '<DomainCheckResult Domain='
        last = 'Available='
        tf_f = 'Available='
        tf_l = 'ErrorNo='
        domain = find_between( line, first, last )
        avail = find_between( line, tf_f, tf_l )
        domain = domain.translate(None, '"')
        avail = avail.translate(None, '"')
        domain = domain.strip()
        avail = avail.strip()
        print domain,avail#true if available, false if not




