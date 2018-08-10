#!/usr/bin/env python

import sys
import requests
import json
import logging
import logging.handlers

SYSLOG_SERVER = 'ip' #IP of the Syslog Server - e.g. McAfee ESM
SYSLOG_PORT = 514 #UDP port
VIRUS_TOTAL_URL = 'https://www.virustotal.com/vtapi/v2/'
APIKEY = 'apikey' #API Key from Virustotal

def file_report(hash):
    params = {'apikey': APIKEY, 'resource': hash}
    headers = { 'Accept-Encoding': 'gzip, deflate'}
    response = requests.get(VIRUS_TOTAL_URL + 'file/report',
        params=params, headers=headers)

    return response.json()

def ip_report(apikey, ip):
    params = {'apikey': APIKEY, 'ip': ip}
    headers = { 'Accept-Encoding': 'gzip, deflate'}
    response = requests.get(VIRUS_TOTAL_URL + 'ip-address/report',
        params=params, headers=headers)

    return response.json()

def file_parser(report):
    try: md5 = report['md5']
    except: md5 = 'not available'

    try: sha1 = report['sha1']
    except: sha1 = 'not available'

    try: sha256 = report['sha256']
    except: sha256 = 'not available'

    msg = report['verbose_msg']
    print msg

    try: positives = report['positives']
    except: positives = 'not available'

    try: total = report['total']
    except: total = 'not available'

    score = '{0}/{1}'.format(positives, total)
    return md5, sha1, sha256, msg, score

def ip_parser(report):
    try: country = report['country']
    except: country = 'not available'

    try: as_owner = report['as_owner']
    except: as_owner = 'not available'

    msg = report['verbose_msg']
    exists = 0

    try:
        for urls in report['detected_urls']:
            exists = 1
    except:
        pass

    try:
        for samples in report['detected_communicating_samples']:
            exists = 1
    except:
        pass

    if exists == 1:
        score = 'Suspicious URL'
    else:
        score = 'Not Suspicious URL'

    return country, as_owner, msg, score

def file_syslog(md5, sha1, sha256, msg, score):
    syslogger = logging.getLogger('Virustotal Log')
    syslogger.setLevel(logging.INFO)
    handler = logging.handlers.SysLogHandler(address=(SYSLOG_SERVER, SYSLOG_PORT))

    syslogger.addHandler(handler)
    message = 'CEF:0|Virustotal|VT|1.0|Alert|FileLookup|5|cs1Label=MD5 cs1={0} cs2Label=SHA1 cs2={1} cs3Label=SHA256 cs3={2} cs4Label=MSG cs4={3} cs5Label=SCORE cs5={4} cat=Lookup'.format(md5, sha1, sha256, msg, score)
    syslogger.info(message)

def ip_syslog(ip, country, as_owner, msg, score):
    syslogger = logging.getLogger('Virustotal Log')
    syslogger.setLevel(logging.INFO)
    handler = logging.handlers.SysLogHandler(address=(SYSLOG_SERVER, SYSLOG_PORT))

    syslogger.addHandler(handler)
    message = 'CEF:0|Virustotal|VT|1.0|Alert|IPLookup|5|cs1Label=IP cs1={0} cs2Label=Country cs2={1} cs3Label=as_owner cs3={2} cs4:Label=MSG cs4={3} cs5Label=SCORE cs5={4} cat=Lookup'.format(ip, country, as_owner, msg, score)
    syslogger.info(message)

if __name__ == "__main__":

    lookup = sys.argv[1]
    value = sys.argv[2]

    if (lookup != 'hash') and (lookup != 'ip'):
        print('Please choose a lookup (hash or ip)')
        sys.exit(1)

    if lookup == 'hash':
        report = file_report(value)
        md5, sha1, sha256, msg, score = file_parser(report)
        file_syslog(md5, sha1, sha256, msg, score)
    elif lookup == 'ip':
        report = ip_report(value)
        country, as_owner, msg, score = ip_parser(report)
        ip_syslog(value, country, as_owner, msg, score)

    print('Virustotal Result: {0}'.format(score))
