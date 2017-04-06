"""
Email parser - extracts all pertinent data from email headers. Works for Outlook (*.msg) and *.eml

* runs against directory with emails, modify the email_file_path parameter

requires extractor_class_emails.py - available in repo

"""

import os
import sys
import glob
import traceback
from email.parser import Parser as EmailParser
import email.utils
import olefile as OleFile

from email.parser import Parser
from extractor_class_emails import cRegexSearcher
import requests
import re

import smtplib
import mimetypes
from email.mime.multipart import MIMEMultipart
from email import encoders
from email.message import Message
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.text import MIMEText
import time
from datetime import date, timedelta
import socket


email_file_path = ''#path to email files
files_to_process = os.listdir(email_file_path)



def search_is_domain(strg, search=re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,7}$", re.I).search):
    return bool(search(strg))

def search_is_bogon(strg, search=re.compile(r"^(^127\.0)|(^192\.168)|(^10\.)|(^172\.1[6-9])|(^172\.2[0-9])|(^172\.3[0-1])$", re.I).search):
    return bool(search(strg))

def search_is_IP(strg, search=re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", re.I).search):
    return bool(search(strg))

def process_sendingip(email,header):#new!
    header = str(header)

    all_recv = []
    all_send = []

    master_send = []
    master_recv = []

    master_send_recv = []

    recv_chain = header.count("Received: from")
    #print 'count recv '+str(recv_chain)

    msg_id_split = header.split('Message-ID: ')

    #print len(msg_id_split)

    recv_chain_split = msg_id_split[0].split('Received: from')
    #print len(recv_chain_split)

    recv_chain_preproc = recv_chain_split[1:]

    #print recv_chain_preproc[-1]
    #print len(recv_chain_preproc)

    if len(recv_chain_preproc) >= 2:

        
        all_recv.append(','.join(recv_chain_preproc[:-1]))

        last_link = recv_chain_preproc[-1]

        last_link_prec_proc = last_link.split()
        try:

            by = last_link_prec_proc.index('by')

            all_send.append(last_link_prec_proc[:by])
            #print 'all send '+str(all_send)

            for item in last_link_prec_proc[by+1:]:
                if search_is_domain(item):
                    all_recv.append(item)
                    break
        except:
            #raise
            print 'exception on '+email
    #print 'recv '+str(all_recv)
    #print 'sendingnn '+str(all_send)

    if len(recv_chain_preproc) == 1:

        last_link_prec_proc = recv_chain_preproc[0].split()
        try:

            by = last_link_prec_proc.index('by')

            all_send.append(last_link_prec_proc[:by])

            for item in last_link_prec_proc[by+1:]:
                if search_is_domain(item):
                    all_recv.append(item)
                    break
        except:
            #raise
            print 'exception on '+email
            
    #print 'recv '+str(all_recv)
    #print 'sendingnn '+str(all_send)        

    search = cRegexSearcher(all_recv)
    matches = search.regexSearch()
    for k, v in matches:
        vstr = str(v)
        kstr = str(k)
        master_recv.append(kstr)            
        

    search = cRegexSearcher(all_send)
    matches = search.regexSearch()
    for k, v in matches:
        vstr = str(v)
        kstr = str(k)
        master_send.append(kstr)   

    master_recv = list(set(master_recv))
    master_send = list(set(master_send))

    for m in master_recv:
        if m not in master_send:
            if search_is_domain(m):
                master_send_recv.append(['receiving_domain',m])
            if search_is_IP(m) and not search_is_bogon(m):
                master_send_recv.append(['receiving_ip',m])

    for m in master_send:
        if search_is_domain(m):
            master_send_recv.append(['sending_domain',m])
        if search_is_IP(m) and not search_is_bogon(m):
            master_send_recv.append(['sending_ip',m])

    #print master_send_recv

    return master_send_recv


def windowsUnicode(string):
    if string is None:
        return None
    if sys.version_info[0] >= 3:  # Python 3
        return str(string, 'utf_16_le')
    else:  # Python 2
        return unicode(string, 'utf_16_le')


class Message(OleFile.OleFileIO):
    def __init__(self, filename):
        OleFile.OleFileIO.__init__(self, filename)

    def _getStream(self, filename):
        if self.exists(filename):
            stream = self.openstream(filename)
            return stream.read()
        else:
            return None

    def _getStringStream(self, filename, prefer='unicode'):
        """Gets a string representation of the requested filename.
        Checks for both ASCII and Unicode representations and returns
        a value if possible.  If there are both ASCII and Unicode
        versions, then the parameter /prefer/ specifies which will be
        returned.
        """

        if isinstance(filename, list):
            # Join with slashes to make it easier to append the type
            filename = "/".join(filename)

        asciiVersion = self._getStream(filename + '001E')
        unicodeVersion = windowsUnicode(self._getStream(filename + '001F'))
        if asciiVersion is None:
            return unicodeVersion
        elif unicodeVersion is None:
            return asciiVersion
        else:
            if prefer == 'unicode':
                return unicodeVersion
            else:
                return asciiVersion

    @property
    def subject(self):
        return self._getStringStream('__substg1.0_0037')

    @property
    def header(self):
        try:
            return self._header
        except Exception:
            headerText = self._getStringStream('__substg1.0_007D')
            if headerText is not None:
                self._header = EmailParser().parsestr(headerText)
            else:
                self._header = None
            return self._header

    @property
    def date(self):
        # Get the message's header and extract the date
        if self.header is None:
            return None
        else:
            return self.header['date']

    @property
    def parsedDate(self):
        return email.utils.parsedate(self.date)

    @property
    def sender(self):
        try:
            return self._sender
        except Exception:
            # Check header first
            if self.header is not None:
                #print self.header
                headerResult = self.header["from"]
                if headerResult is not None:
                    self._sender = headerResult
                    return headerResult

            # Extract from other fields
            text = self._getStringStream('__substg1.0_0C1A')
            email = self._getStringStream('__substg1.0_0C1F')
            result = None
            if text is None:
                result = email
            else:
                result = text
                if email is not None:
                    result = result + " <" + email + ">"

            self._sender = result
            return result

    #@property
    def complete_header(self):
        try:
            return self.header
        except:
            return ''

    @property
    def to(self):
        try:
            return self._to
        except Exception:
            # Check header first
            if self.header is not None:
                headerResult = self.header["to"]
                if headerResult is not None:
                    self._to = headerResult
                    return headerResult

            # Extract from other fields
            # TODO: This should really extract data from the recip folders,
            # but how do you know which is to/cc/bcc?
            display = self._getStringStream('__substg1.0_0E04')
            self._to = display
            return display

    @property
    def cc(self):
        try:
            return self._cc
        except Exception:
            # Check header first
            if self.header is not None:
                headerResult = self.header["cc"]
                if headerResult is not None:
                    self._cc = headerResult
                    return headerResult

            # Extract from other fields
            # TODO: This should really extract data from the recip folders,
            # but how do you know which is to/cc/bcc?
            display = self._getStringStream('__substg1.0_0E03')
            self._cc = display
            return display

    @property
    def body(self):
        # Get the message body
        return self._getStringStream('__substg1.0_1000')


    def print_meta(self, raw=False):

        def xstr(s):
            return '' if s is None else str(s)

        return xstr(self.sender),xstr(self.to),xstr(self.cc),xstr(self.subject)



writeRaw = False
toJson = False
useFileName = False





for email in files_to_process:

    parsed_email_data = []

    email_file = email_file_path+email

    

    try:
        msg = Message(email_file)
        
        msg_output = msg.print_meta()
        sender = msg_output[0]
        to = msg_output[1]
        cc = msg_output[2]
        sub = msg_output[3]

        temp_domains = []

        header = msg.complete_header()


        results = process_sendingip(email,header) #new!

        if results is not None:#new!
            for r in results:  #new!                 
                parsed_email_data.append([email,r[0],r[1],'eml'])#new!



        if sender != '' and sender is not None:
            parsed_email_data.append([email,'sender_field',sender,'msg'])
            search = cRegexSearcher(to)
            matches = search.regexSearch()
            for k, v in matches:
                vstr = str(v)
                kstr = str(k)
                if vstr == 'email':
                    parsed_email_data.append([email,'sender_email',kstr,'msg'])
                if vstr == 'fqdn':
                    parsed_email_data.append([email,'sender_domain',kstr,'msg'])
                    temp_domains.append(kstr)

            
        if cc != '' and cc is not None:
                search = cRegexSearcher(to)
                matches = search.regexSearch()
                for k, v in matches:
                    vstr = str(v)
                    kstr = str(k)
                    if vstr == 'email':
                        parsed_email_data.append([email,'cc_email',kstr,'msg'])
                    if vstr == 'fqdn':
                        parsed_email_data.append([email,'cc_domain',kstr,'msg'])
                        temp_domains.append(kstr)

        if sub != '' and sub is not None:
            parsed_email_data.append([email,'subject_line',sub,'msg'])

        if to != '' and to is not None:
            search = cRegexSearcher(to)
            matches = search.regexSearch()
            for k, v in matches:
                vstr = str(v)
                kstr = str(k)
                if vstr == 'email':
                    parsed_email_data.append([email,'to_email',kstr,'msg'])
                if vstr == 'fqdn':
                    parsed_email_data.append([email,'to_domain',kstr,'msg'])
                    temp_domains.append(kstr)



        temp_domains = []
                    
            
    except:
        with open(email_file) as fp:
            headers = Parser().parse(fp)

            
            headers_string = str(headers)#new!
            results = process_sendingip(email,headers_string)#new!

            if results is not None:#new!
                for r in results:#new!                   
                    parsed_email_data.append([email,r[0],r[1],'msg'])#new!




            
            sender = headers['from']
            to = headers['to']
            cc = headers['cc']
            sub = headers['subject']
            received = headers['received']

            #print headers

            temp_domains = []

            if sender != '' and sender is not None:
                parsed_email_data.append([email,'sender_field',sender,'eml'])
                search = cRegexSearcher(to)
                matches = search.regexSearch()
                for k, v in matches:
                    vstr = str(v)
                    kstr = str(k)
                    if vstr == 'email':
                        parsed_email_data.append([email,'sender_email',kstr,'eml'])
                    if vstr == 'fqdn':
                        parsed_email_data.append([email,'sender_domain',kstr,'eml'])
                        temp_domains.append(kstr)

            if to != '' and to is not None:                
                search = cRegexSearcher(to)
                matches = search.regexSearch()
                for k, v in matches:
                    vstr = str(v)
                    kstr = str(k)
                    if vstr == 'email':
                        parsed_email_data.append([email,'to_email',kstr,'eml'])
                    if vstr == 'fqdn':
                        parsed_email_data.append([email,'to_domain',kstr,'eml'])
                        temp_domains.append(kstr)
                
            if cc != '' and cc is not None:
                search = cRegexSearcher(to)
                matches = search.regexSearch()
                for k, v in matches:
                    vstr = str(v)
                    kstr = str(k)
                    if vstr == 'email':
                        parsed_email_data.append([email,'cc_email',kstr,'eml'])
                    if vstr == 'fqdn':
                        parsed_email_data.append([email,'cc_domain',kstr,'eml'])
                        temp_domains.append(kstr)

            if sub != '' and sub is not None:
                parsed_email_data.append([email,'subject_line',sub,'eml'])


    parsed_email_data = list(set(tuple(element) for element in parsed_email_data))
    for p in parsed_email_data:
        print p



