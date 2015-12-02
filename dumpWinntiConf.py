#!/usr/bin/env python2

'''
Created on 2015-10-10

@author: S2R2

Dump config from a winnti worker file

v0.01 S2R2: first shot

'''

import re
import argparse
import binascii
import hashlib
from struct import unpack_from

def xorStrHex(str1,key):
    decoded = ''
#    orgKey = key
    for c in str1:
        decoded = decoded + chr(ord(c)^key)
        key = key + 1
        if(key > 0xff):
            key = 0x00
    return decoded

def getContentFromFile(path):
    with open(path,"rb") as inFile:
        data = inFile.read()
    inFile.close()
    return data

def getMd5Hash(s):
    m = hashlib.md5()
    m.update(s)
    return m.hexdigest()

def writeFile(path,content):
    outFile = open(path,"wb")
    outFile.write(content)
    outFile.close()

def isConfig(config):
    p = re.compile("^[a-zA-Z0-9.-]{4}[a-zA-Z0-9.:-]+")
    if p.match(config):
        return True
    return False

def extractConfig(confStr):
    extract =  unpack_from("100s32s32s24s4s4s4si4s32s32s32s21h4s",confStr)
    conf = {
          'szC2': extract[0],
          'szCampaignID1': extract[1],
          'szCampaignID2': extract[2],
          'szCampaignIDNumber': extract[3],
          'unknown0': binascii.hexlify(extract[4]),
          'unknown1': binascii.hexlify(extract[5]),
          'unknown2': binascii.hexlify(extract[6]),
          'dwCommMode': extract[7],
          'dwProxyType': binascii.hexlify(extract[8]),
          'szProxyServer': extract[9],
          'szProxyUser': extract[10],
          'szProxyPassword': extract[11],
          'ActivePeriods': [
                            {
                            'wDayOfWeek': extract[12],
                            'wStartTime': extract[13],
                            'wEndTime': extract[14]
                            },
                            {
                            'wDayOfWeek': extract[15],
                            'wStartTime': extract[16],
                            'wEndTime': extract[17]
                            },
                            {
                            'wDayOfWeek': extract[18],
                            'wStartTime': extract[19],
                            'wEndTime': extract[20]
                            },
                            {
                            'wDayOfWeek': extract[21],
                            'wStartTime': extract[22],
                            'wEndTime': extract[23]
                            },
                            {
                            'wDayOfWeek': extract[24],
                            'wStartTime': extract[25],
                            'wEndTime': extract[26]
                            },
                            {
                            'wDayOfWeek': extract[27],
                            'wStartTime': extract[28],
                            'wEndTime': extract[29]
                            },
                            {
                            'wDayOfWeek': extract[30],
                            'wStartTime': extract[31],
                            'wEndTime': extract[32]
                            }
                            ],
          'iReconnectTime': unpack_from('i',extract[33])[0]
          }
    
    if conf['dwCommMode'] == 1:
        conf['dwCommMode'] = '1 (Custom TCP)'
    elif conf['dwCommMode'] == 2:
        conf['dwCommMode'] = '2 (HTTPS)'
    elif conf['dwCommMode'] == 3:
        conf['dwCommMode'] = '3 (HTTP)'
    else:
        conf['dwCommMode'] = str(conf['dwCommMode']) + '(Unknown)'
        
    return conf

def config2string(conf):
    
    confStr = "c2: " + str(conf['szC2']) + "\n"
    confStr = confStr + "CampaignID1: " + conf['szCampaignID1'] + "\n"
    confStr = confStr +  "CampaignID2: " + conf['szCampaignID2'] + "\n"
    confStr = confStr +  "CampaignIDNumber: " + conf['szCampaignIDNumber'] + "\n"
    confStr = confStr +  "unknown0: " + conf['unknown0'] + "\n"
    confStr = confStr +  "unknown1: " + conf['unknown1'] + "\n"
    confStr = confStr +  "unknown2: " + conf['unknown2'] + "\n"
    confStr = confStr +  "CommMode: " + conf['dwCommMode'] + "\n"
    confStr = confStr +  "ProxyType: " + conf['dwProxyType'] + "\n"
    confStr = confStr +  "ProxyServer: " + conf['szProxyServer'] + "\n"
    confStr = confStr +  "ProxyUser: " + conf['szProxyUser'] + "\n"
    confStr = confStr +  "ProxyPassword: " + conf['szProxyPassword'] + "\n"
    confStr = confStr +  "ActivePeriods: " + "\n"
    for i in range(len(conf['ActivePeriods'])):
        confStr = confStr +  "\tScheduleEntry: " + str(i) + "\n"
        confStr = confStr +  "\t\tDayOfWeek: " + str(conf['ActivePeriods'][i]['wDayOfWeek']) + "\n"
        confStr = confStr +  "\t\tStartTime: " + str(conf['ActivePeriods'][i]['wStartTime']) + "\n"
        confStr = confStr +  "\t\tEndTime: " + str(conf['ActivePeriods'][i]['wEndTime']) + "\n"
    confStr = confStr +  "ReconnectTime: " + str(conf['iReconnectTime']) + "\n"
    
    return confStr

def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', help='Specify the winnti worker file', action='store', dest='winntiFile', required=True)
    parser.add_argument('-s', help='Print config to the screen', action='store_true',dest='screen',  required=False)
    parser.add_argument('-w', help='Write config as binary struct', action='store', dest='binfile', required=False)
    parser.add_argument('-t', help='Write config as text', action='store', dest='txtfile', required=False)
    args = parser.parse_args()
    
    winntiFile = args.winntiFile

    data = getContentFromFile(winntiFile)
    print "Analysing file " + getMd5Hash(data)
    
    configStart = len(data) - (unpack_from("i",data[len(data)-4:])[0] +4)
    print "Config offset is " + str(hex(configStart))
    decoded=xorStrHex(data[configStart:configStart+350], 0x99)
    
    if (isConfig(decoded) == False):
        print "No config found. Please check if the file is a Winnti Worker"
        exit()
    
    conf = extractConfig(decoded)
    if args.screen:
        print "----------------------------------------------------"
        print config2string(conf)
        print "----------------------------------------------------"
    
    if args.binfile:
        print "Writing binary struct to " + args.binfile
        writeFile(args.binfile, decoded)

    if args.txtfile:
        print "Writing config text to " + args.txtfile
        writeFile(args.txtfile, config2string(conf))
        
        
if __name__ == '__main__':
    main()