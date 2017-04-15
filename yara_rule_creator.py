
"""
This script may be used to create a simple yara rule using an input file of domains or IPs. Useful if you have a large amount of domains or IPs , where manual rule creation is not practical

Usage:
1. Modify the rule_name parameter below to the name of the yara rule.(the name doesnt matter but make sure there are not spaces)
2. Modify the rule_strings parameter to the name of the input file. The input file must have a list of keywords.
3. end rule with _domains to create domain rule, _emails to create email rule, _ips to create IP rule


"""

import re
import os
import hashlib


#your Yara rule name, must end with _domains, _emails, or _ips
rule_name = 'samplerule_domains'

#input file with domains, or IPs
rule_strings = 'domain_test.txt'


keyword_list = []
keyword_strings = []


if os.path.exists(rule_strings) and os.access(rule_strings, os.R_OK):
    f_in = open(rule_strings)
    for _line in f_in.readlines():
        _line = _line.strip()
        keyword_list.append(_line)

        

        f_in.close()


yara_rule_file = rule_name+'_rule'+'.txt'

keyword_list = list(set(keyword_list))


f = open(yara_rule_file,"w")


f.write('rule '+rule_name+'\n')

f.write('{\n')

f.write('strings:\n')
for item in keyword_list:
    hash_object = hashlib.md5(item.encode())
    hash1 = (hash_object.hexdigest())
    yara_id = hash1[:8]

    item = item.replace('.','\\.')

    
    if rule_name.endswith('_emails'):         
        item1 =  "/\\b([A-Z0-9._%+-]+@"+item+")\\b/ nocase"
    if rule_name.endswith('_domains') or rule_name.endswith('_ips'):
        item1 = '/\\b('+item+')\\b/ nocase'


    f.write('$string_'+yara_id+' = '+item1)
    f.write('\n')


f.write('\n')
f.write('condition:\n')
f.write('\n')
f.write('any of ($s*)')
f.write('\n')
f.write('}\n')
f.write('\n')

f.close()




print 'Success! Created Yara rule file named ',yara_rule_file


