#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
from Crypto.Cipher import AES
from ftplib import FTP
import hashlib
import os, sys, os.path
import re
import time
import urllib2
import xml.dom.minidom
from xml.dom.minidom import Node
import urllib
import simplejson

import subprocess # by bop
# ich mag einfach wget da seh ich was auch geladen wird

def banner():
    print "         _______\)%%%%%%%%._"
    print "        `''''-'-;   % % % % %'-._"
    print "                :b) \            '-."
    print "                : :__)'    .'    .'  Paranoid Unicorns"
    print "                :.::/  '.'   .'           presents"
    print "                o_i/   :    ;              pySFDL"
    print "                       :   .'          modded by bop"
    print "                        ''`                 2019"
    print "=========================[USAGE]========================="
    print ""
    print "$ python %s datei.sfdl [password]" % (sys.argv[0])
    print ""
    print "========================================================="


def handleDownload(block):
        file.write(block)
        print ".",

def getChildrenBylocalName(node, localNameVar):
        for child in node.childNodes:
            if child.localName==localNameVar:
                yield child

def is_file(filename):
    current = ftp.pwd()
    try:
        ftp.cwd(filename)
    except:
        ftp.cwd(current)
        return True
    ftp.cwd(current)
    return False

def decrypt(cypher, password):
    AES.key_size=128
    iv=cypher[:16]
    key=hashlib.md5(password).digest()
    crypt_object=AES.new(key=key,mode=AES.MODE_CBC,IV=iv)

    decoded=base64.b64decode(cypher)
    decrypted=crypt_object.decrypt(decoded)


    stripped = decrypted.strip()
    result = decrypted[16:len(decrypted)]
    delete = ""
    i=1

    while (i<0x20):
        delete += chr(i)
        i += 1
    t = result.translate(None,delete)
    return t

def getSFDLVersion(dom):
    SFDLFileVersion = None
    Topic=dom.getElementsByTagName('SFDLFile')
    for node in Topic:
        alist=getChildrenBylocalName(node, 'SFDLFileVersion')
        for a in alist:
            SFDLFileVersion= a.childNodes[0].nodeValue
    if SFDLFileVersion == None:
        Topic=dom.getElementsByTagName('SFDL_File')
        for node in Topic:
            alist=getChildrenBylocalName(node, 'GetSetFileVersion')
            for a in alist:
                SFDLFileVersion= a.childNodes[0].nodeValue
    return SFDLFileVersion

def getEncryptionStatus(dom):
    EncryptionStatus = None
    Topic=dom.getElementsByTagName('SFDLFile')
    for node in Topic:
        alist=getChildrenBylocalName(node, 'Encrypted')
        for a in alist:
            EncryptionStatus= a.childNodes[0].nodeValue
    if EncryptionStatus == None:
        Topic=dom.getElementsByTagName('SFDL_File')
        for node in Topic:
            alist=getChildrenBylocalName(node, 'GetSetEncryptet')
            for a in alist:
                EncryptionStatus= a.childNodes[0].nodeValue
    return EncryptionStatus

def getBulkFolderMode(dom):
    BulkFolderMode = None
    Topic=dom.getElementsByTagName('Packages')
    for node in Topic:
        Topic=dom.getElementsByTagName('SFDLPackage')
        for node in Topic:
            alist=getChildrenBylocalName(node, 'BulkFolderMode')
            for a in alist:
                BulkFolderMode=a.childNodes[0].nodeValue
    if BulkFolderMode == "true": return True
    else: return False

def getAuthRequiredMode(dom):
    AuthRequiredMode = None
    Topic=dom.getElementsByTagName('SFDLFile')
    for node in Topic:
        Topic=dom.getElementsByTagName('ConnectionInfo')
        for node in Topic:
            alist=getChildrenBylocalName(node, 'AuthRequired')
            for a in alist:
                AuthRequiredMode=a.childNodes[0].nodeValue
        if AuthRequiredMode == "true": return True
    else: return False

def getIPLocation(ip):
    url = "http://ip-api.com/json/"+ip
    try:
        json = urllib2.urlopen(url).read()
        #~ json = subprocess.check_output('wget -O- "{url}"'.format(url=url), shell=True)
    except:
        return None
    data = simplejson.loads(json)
    location = data["countryCode"]
    location += ' | '+data["country"]
    location += ' | '+data["city"]
    location += ' | '+data["as"]
    location += ' | '+data["isp"]
    location += ' | '+data["org"]
    return location



# convert size to MB GB or what ever yeah
def convertSize(size):
    '''
    source: http://stackoverflow.com/questions/5194057/better-way-to-convert-file-sizes-in-python
    '''
    size_name = ("KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size,1024)))
    p = math.pow(1024,i)
    s = round(size/p,2)
    if (s > 0):
       return '%s %s' % (s,size_name[i])
    else:
       return '0B'

if __name__ == "__main__":
    try:
        if len(sys.argv) > 3 or len(sys.argv) < 2:
            banner()
        else:
            dom = xml.dom.minidom.parse(sys.argv[1])
            sfdlversion = getSFDLVersion(dom)
            encrypted = getEncryptionStatus(dom)
            bulkfoldermode = getBulkFolderMode(dom)
            AuthRequiredMode = getAuthRequiredMode(dom)

            if encrypted == "true" and len(sys.argv) < 3:
                print "Da diese SFDL verschluesselt ist muessen sie ein Passwort mitgeben."
                exit(1)

            if encrypted == "true" and sfdlversion == "4":
                print "1"
                Topic = dom.getElementsByTagName('SFDL_File')
                for node in Topic:
                    alist = getChildrenBylocalName(node, 'GetSetDescription')
                    for a in alist:
                        description = a.childNodes[0].nodeValue
                        description = decrypt(description, sys.argv[2])
                    alist = getChildrenBylocalName(node, 'GetsetUploader')
                    for a in alist:
                        uploader = a.childNodes[0].nodeValue
                        uploader = decrypt(uploader, sys.argv[2])
                    Topic = dom.getElementsByTagName('GetSetConnectionInfo')
                    for node in Topic:
                        alist = getChildrenBylocalName(node, 'GetSetHost')
                        for a in alist:
                            host = a.childNodes[0].nodeValue
                            host = decrypt(host, sys.argv[2])
                        alist = getChildrenBylocalName(node, 'GetSetPort')
                        for a in alist:
                            port = a.childNodes[0].nodeValue
                        alist = getChildrenBylocalName(node, 'GetSetUsername')
                        for a in alist:
                            username = a.childNodes[0].nodeValue
                            username = decrypt(username, sys.argv[2])
                        alist = getChildrenBylocalName(node, 'GetSetPassword')
                        for a in alist:
                            password = a.childNodes[0].nodeValue
                            password = decrypt(password, sys.argv[2])
                    Topic = dom.getElementsByTagName('GetSetFileInfoList')
                    for node in Topic:
                        Topic = dom.getElementsByTagName('FileInfo')
                        for node in Topic:
                            alist = getChildrenBylocalName(node, 'GetSetDirectoryRoot')
                            for a in alist:
                                directory = a.childNodes[0].nodeValue
                                directory = decrypt(directory, sys.argv[2])

            if encrypted == "true" and sfdlversion == "6" or encrypted == "true" and sfdlversion == "8":
                print "2"
                Topic = dom.getElementsByTagName('SFDLFile')
                for node in Topic:
                    alist = getChildrenBylocalName(node, 'Description')
                    for a in alist:
                        description = a.childNodes[0].nodeValue
                        description = decrypt(description, sys.argv[2])
                    alist = getChildrenBylocalName(node, 'Uploader')
                    for a in alist:
                        uploader = a.childNodes[0].nodeValue
                        uploader = decrypt(uploader, sys.argv[2])
                    Topic = dom.getElementsByTagName('ConnectionInfo')
                    for node in Topic:
                        alist = getChildrenBylocalName(node, 'Host')
                        for a in alist:
                            host = a.childNodes[0].nodeValue
                            host = decrypt(host, sys.argv[2])
                        alist = getChildrenBylocalName(node, 'Port')
                        for a in alist:
                            port = a.childNodes[0].nodeValue
                        alist = getChildrenBylocalName(node, 'Username')
                        for a in alist:
                            print a.childNodes
                            try:
                                username = a.childNodes[0].nodeValue
                                username = decrypt(username, sys.argv[2])
                            except:
                                pass
                        alist = getChildrenBylocalName(node, 'Password')
                        for a in alist:
                            try:
                                password = a.childNodes[0].nodeValue
                                password = decrypt(password, sys.argv[2])
                            except:
                                pass
                    Topic = dom.getElementsByTagName('Packages')
                    for node in Topic:
                        Topic = dom.getElementsByTagName('SFDLPackage')
                        for node in Topic:
                            Topic = dom.getElementsByTagName('FileList')
                            print Topic
                            for node in Topic:
                                Topic = dom.getElementsByTagName('FileInfo')
                                for node in Topic:
                                    alist = getChildrenBylocalName(node, 'DirectoryPath')
                                    for a in alist:
                                        directory = a.childNodes[0].nodeValue
                                        directory = decrypt(directory, sys.argv[2])
                    try:
                        #~ # littel bugfix with directory
                        #~ # why machen sich es eigntlich alle sooo schwer?
                        #~ # der bash loader: scheiße
                        #~ # der py loadder: 50% scheiße
                        #~ # ey was los mit euch noch nie was von wget curl und so gehört?
                        #~ # damit könnte man sich das alles so einfach machen aber ne
                        #~ # auf MLC will ja jeder der coolste und schlauste sein
                        #~ # da werden halt skripte gecodet mit 90% müll den man nicht
                        #~ # braucht
                        #~ # und das beste in scene bereich meine scan und hacktoolz und
                        #~ # ich werde aus dem bereich geworfen
                        #~ # das ich euch nicht schämt
                        #~ # fucking noobs...
                        h = open(sys.argv[1])
                        sfdl_string = h.read(); h.close()
                        m = re.search(r'BulkFolderPath>([^\<]+)</BulkFolderPath', sfdl_string, re.I)
                        directory = decrypt( m.group(1), sys.argv[2])
                    except:
                        pass



            if encrypted == "false" and sfdlversion == "4":
                print "3"
                Topic = dom.getElementsByTagName('SFDL_File')
                for node in Topic:
                    alist = getChildrenBylocalName(node, 'GetSetDescription')
                    for a in alist:
                        description = a.childNodes[0].nodeValue
                    alist = getChildrenBylocalName(node, 'GetsetUploader')
                    for a in alist:
                        uploader = a.childNodes[0].nodeValue
                    Topic = dom.getElementsByTagName('GetSetConnectionInfo')
                    for node in Topic:
                        alist = getChildrenBylocalName(node, 'GetSetHost')
                        for a in alist:
                            host = a.childNodes[0].nodeValue
                        alist = getChildrenBylocalName(node, 'GetSetPort')
                        for a in alist:
                            port = a.childNodes[0].nodeValue
                        alist = getChildrenBylocalName(node, 'GetSetUsername')
                        for a in alist:
                            username = a.childNodes[0].nodeValue
                        alist = getChildrenBylocalName(node, 'GetSetPassword')
                        for a in alist:
                            password = a.childNodes[0].nodeValue
                    Topic = dom.getElementsByTagName('GetSetFileInfoList')
                    for node in Topic:
                        Topic = dom.getElementsByTagName('FileInfo')
                        for node in Topic:
                            alist = getChildrenBylocalName(node, 'GetSetDirectoryRoot')
                            for a in alist:
                                directory = a.childNodes[0].nodeValue


            if encrypted == "false" and sfdlversion >= "6" and bulkfoldermode == False or encrypted == "false"  and sfdlversion >= "8" and bulkfoldermode == False:
                print "4"
                Topic = dom.getElementsByTagName('SFDLFile')
                for node in Topic:
                    alist = getChildrenBylocalName(node, 'Description')
                    for a in alist:
                        description = a.childNodes[0].nodeValue
                    alist = getChildrenBylocalName(node, 'Uploader')
                    for a in alist:
                        uploader = a.childNodes[0].nodeValue
                    Topic = dom.getElementsByTagName('ConnectionInfo')
                    for node in Topic:
                        alist = getChildrenBylocalName(node, 'Host')
                        for a in alist:
                            host = a.childNodes[0].nodeValue
                        alist = getChildrenBylocalName(node, 'Port')
                        for a in alist:
                            port = a.childNodes[0].nodeValue
                        alist = getChildrenBylocalName(node, 'Username')
                        for a in alist:
                            if AuthRequiredMode == True: username = a.childNodes[0].nodeValue
                        alist = getChildrenBylocalName(node, 'Password')
                        for a in alist:
                            if AuthRequiredMode == True: password = a.childNodes[0].nodeValue
                    Topic = dom.getElementsByTagName('Packages')
                    for node in Topic:
                        Topic = dom.getElementsByTagName('SFDLPackage')
                        for node in Topic:
                            Topic = dom.getElementsByTagName('FileList')
                            for node in Topic:
                                Topic = dom.getElementsByTagName('FileInfo')
                                for node in Topic:
                                    alist = getChildrenBylocalName(node, 'DirectoryPath')
                                    for a in alist:
                                        directory = a.childNodes[0].nodeValue

            if encrypted == "false" and sfdlversion >= "6" and bulkfoldermode == True or encrypted == "false" and sfdlversion >= "8" and bulkfoldermode == True:
                print "5"
                Topic = dom.getElementsByTagName('SFDLFile')
                for node in Topic:
                    alist = getChildrenBylocalName(node, 'Description')
                    for a in alist:
                        description = a.childNodes[0].nodeValue
                    alist = getChildrenBylocalName(node, 'Uploader')
                    for a in alist:
                        uploader = a.childNodes[0].nodeValue
                    Topic = dom.getElementsByTagName('ConnectionInfo')
                    for node in Topic:
                        alist = getChildrenBylocalName(node, 'Host')
                        for a in alist:
                            host = a.childNodes[0].nodeValue
                        alist = getChildrenBylocalName(node, 'Port')
                        for a in alist:
                            port = a.childNodes[0].nodeValue
                        alist = getChildrenBylocalName(node, 'Username')
                        for a in alist:
                            if AuthRequiredMode == True: username = a.childNodes[0].nodeValue
                        alist = getChildrenBylocalName(node, 'Password')
                        for a in alist:
                            if AuthRequiredMode == True: password = a.childNodes[0].nodeValue
                    Topic = dom.getElementsByTagName('Packages')
                    for node in Topic:
                        Topic = dom.getElementsByTagName('SFDLPackage')
                        for node in Topic:
                            Topic = dom.getElementsByTagName('BulkFolderList')
                            for node in Topic:
                                Topic = dom.getElementsByTagName('BulkFolder')
                                for node in Topic:
                                    alist = getChildrenBylocalName(node, 'BulkFolderPath')
                                    for a in alist:
                                        directory = a.childNodes[0].nodeValue


            if AuthRequiredMode == False:
                username = "anonymous"
                password = "anonymous@anonymous.de"
            if not os.path.exists(description):
                os.mkdir(description)

            print "         _______\)%%%%%%%%._"
            print "        `''''-'-;   % % % % %'-._"
            print "                :b) \            '-."
            print "                : :__)'    .'    .'  Paranoid Unicorns"
            print "                :.::/  '.'   .'           presents"
            print "                o_i/   :    ;              pySFDL"
            print "                       :   .'"
            print "                        ''`"
            print "====================[SFDL INFORMATION]==================="
            print "Description: %s" % (description)
            print "Uploader: %s" % (uploader)
            print "SFDL Version: %s" % (sfdlversion)
            print "Encrypted: %s" % (encrypted)
            print "BulkFolderMode: %r" % (bulkfoldermode)
            print "AuthRequiredMode: %r" % (AuthRequiredMode)
            print "========================================================="
            print ""
            print "==================[SERVER INFORMATION]==================="
            print "Host: %s" % (host)
            print "Port: %s" % (port)
            print "Username: %s" % (username)
            print "Password: %s" % (password)
            print "FolderPath: %s" % (directory)
            country = getIPLocation(host)
            print "Country: %s" % (country)
            print "========================================================="
            print ""
            ftp_url = 'ftp://{host}:{port}/{directory}'.format(username=username, password=password, host=host, port=port, directory=directory.lstrip('/'))
            #~ ftp_url = 'ftp://{username}:{password}@{host}:{port}/{directory}'.format(username=username, password=password, host=host, port=port, directory=directory.lstrip('/'))
            titel = sys.argv[1].replace('.sfdl', '').strip('/').split('/').pop()
            try:
                os.mkdir(titel)
            except:
                pass
            #~ speicher in hsitory
            #~ if country:
                #~ h = open('pySFDL.history', 'a+')
                #~ h.write(str(country).decode('utf-8')+'\n')
                #~ h.write(u''.join([country, '\n']))
                #~ h.write(ftp_url+'\n\n')
                #~ h.close()
            starttime = time.time()
            print "=================[FTP CONNECTION DETAILS]================"
            wget = 'wget -nH -nd -r -c -P "{directory}" --ftp-password="{password}" --ftp-user="{user}" "{url}"'.format(
                    directory=titel, url=ftp_url,
                    password=password, user=username
                )
            print wget
            subprocess.check_output(wget, shell=True)
            print "=================[DOWNLOAD DETAILS]================"
            endtime = time.time() - starttime
            size = subprocess.check_output("du -s \"%s\" |awk '{print $1}'"%titel, shell=True).strip()
            bandwidth = float(size) / float(endtime) / float(1024)
            print "successfully downloaded | Time: %f Size: %s Throughput: %.2f KB/s" % (endtime, convertSize(str(size)), bandwidth)
            
            #~ print "=================[FTP CONNECTION DETAILS]================"
            #~ ftp = FTP()
            #~ print 'Build Connection.'
            #~ ftp.connect(host, int(port))
            #~ print 'Logging in.'
            #~ ftp.login(username, password)
            #~ directory = urllib.unquote(directory)
            #~ print 'Changing to %s' % (directory)
            #~ #ftp.cwd(directory.encode("utf-8"))
            #~ ftp.cwd(directory)
            #~ filenames = []
            #~ ftp.retrlines('NLST', filenames.append)
            #~ print "====================[DOWNLOAD DETAILS]==================="
            #~ print "Download started at "+time.strftime("%a, %d %b %H:%M:%S", time.gmtime())
            #~ for filename in filenames:
                    #~ if is_file(filename):
                        #~ starttime = time.time()
                        #~ ftp.voidcmd('TYPE I')
                        #~ size = ftp.size(filename)
                        #~ local_filename = os.path.join(description+"/", filename)
                        #~ file = open(local_filename, 'wb')
                        #~ ftp.retrbinary('RETR '+ filename, file.write)
                        #~ file.close()
                        #~ endtime = time.time() - starttime
                        #~ bandwidth = size / endtime / 1024
                        #~ print filename+" successfully downloaded | Time: %f Size: %i Throughput: %.2f KB/s" % (endtime, size, bandwidth)
            #~ print "Download stopped at "+time.strftime("%a, %d %b %H:%M:%S", time.gmtime())
            #~ ftp.close()
    except KeyboardInterrupt, error:
        print ""
