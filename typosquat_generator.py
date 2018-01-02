"""
This program takes a starting string and then generates a list of similar permutations. The goal
is to use the outputs to search against domains in order identify typosquatted and/or fraudulent sites.

For example, one could take the outputs of this and use with the domain check script:

https://github.com/wolfpack1/intel_collection_tools/blob/master/DT_domain_checker.py

"""




from itertools import permutations
from difflib import SequenceMatcher
import textwrap
from datetime import date, timedelta
import datetime


initial = 'bankofamerica'#the shorter the better! so long as its an obvious reference

if len(initial) >= 14:
    print 'Any initial over 14 characters will cause issues :('

similar_threshold = .90#how similar should the permutation should be to the initial. .90 is 90% similar

print 'processing typosquat permutations.. this may take a minute..'

def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

first_letter = initial[0]

chunked_out = textwrap.wrap(initial, 7)#break out into consumable chunks..

#print 'chunked out ..',chunked_out
pre_process_chunks = []#creates preliminary permutations to process

for c in chunked_out:
    #print 'chunk ', c
    temp= []
    c_temp = c.replace('l', '1')#account for the 1/l swap trick (number one, in place of letter 'L')
    if c != c_temp:
        temp.append(c_temp)
    c_temp2 = c.replace('-', '')#remove any hyphens 
    if c != c_temp2:
        temp.append(c_temp2)    
    pre2_temp = []
    temp.append(c)
    temp.append(c[1:])
    temp.append(c[1:-1])
    for i in xrange(1,len(c)):
        #print i
        b = bytearray(c)
        del b[i]
        pre1 = str(b)
        temp.append(pre1)

    pre_process_chunks.append(temp)
    #print temp


pre_process_two = []#for each character in perm, double it.. so mydomain is mmydomain, and myydomain, and so on 

for p in pre_process_chunks:
    temp_2 = []

    for c in p:
        temp_2.append(c)
        pre2_temp = []
        
        tcount = 0
        for i in xrange(len(c)):
            #part_one = i
            #part_two 
            l_one = c[:i]
            l_two = c[i:]

            newstring = l_one+c[i]+l_two
            temp_2.append(newstring)
            
    pre_process_two.append(temp_2)

                

typosquat_master = []

pre_process_three = []

all_fin_perms = []
for pm in pre_process_two:
    

    #all_fin_perms = []

    #get all perms of consumable chunks..
    for word in list(set(pm)):
        #print 'getting permutations for ', word
        #perms = [''.join(p) for p in permutations(word)]
        perms = permutations(word)

        #print 'total permutations .. ',len(list(perms))

        for p in perms:

            perm =  ''.join(p)

            if similar(word,perm) > similar_threshold:
                if perm not in all_fin_perms:
                    all_fin_perms.append(perm)

            if word not in all_fin_perms:
                all_fin_perms.append(word)
                
        #print 'processing sub-string ', word
        #print 'total permutations ',len(all_fin_perms)

    pre_process_three.append(all_fin_perms)



#print 'len all perms ', len(pre_process_three)




d_tracker = []
for p in pre_process_three[0]:

    try:
        for p2 in pre_process_three[1]:
            new_t = p+p2

            similar_value = similar(initial,new_t)
            if similar_value > similar_threshold and new_t.startswith(initial[0]):
                if new_t not in d_tracker:
                    #print new_t
                    d_tracker.append(new_t)                    
                    typosquat_master.append([new_t,similar_value])
    except:
        new_t = p
        similar_value = similar(initial,new_t)
        if similar_value > similar_threshold and new_t.startswith(initial[0]):
            if new_t not in d_tracker:
                #print new_t
                d_tracker.append(new_t)
                typosquat_master.append([new_t,similar_value])


                                        
print 'TOTAL TYPOSQUAT PERMUTATIONS ',len(typosquat_master)

for t in typosquat_master:
    
    #print '------------------'

    #print 'perm:',t[0]
    #print 'similarity:',t[1]
    #print 'processed:',t
    print t[0]

