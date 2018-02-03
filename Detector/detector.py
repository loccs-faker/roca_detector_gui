#!/usr/bin/env python 
# -*- coding: utf-8 -*-
"""
Rsa vulnerable keys detector

It is a visualization tool used for detect vulnerable keys mentions in the paper "The Return of Coppersmith’s Atack:Practical 
Factorization of Widely Used RSA Moduli"

The follow formats are supported:
-X509 certificate,pem encoded
-X509 certificate,der encoded
-RSA public key,RSA private key,pem encoded
-ASC encoded PGP key
-SSH public key
-PKCS7 signature with user certificate

Dependencies:

    - sudo apt-get install python-pip python-tk python-dev build-essential libssl-dev libffi-dev swig
package requirements:

    - pip install cryptography pgpdump coloredlogs future six pycrypto>=2.6 python-dateutil pyx509_ph4 apk_parse_ph4
    - try 'pip uninstall M2Crypto' and excute 'sudo apt-get install m2crypto' if you can't import APK when processing 
      '.apk' files

"""
import time
import logging
import coloredlogs
try: 
    from tkinter.ttk import *
except:
    print('\nErrors occured when importing module \'tkinter\',try\'sudo apt-get install python-tk\'\n')
    exit()
from tkinter import StringVar
from tkinter import messagebox
from builtins import bytes
from past.builtins import basestring
import os
import sys
import tkinter
import tkinter.filedialog
import re
import base64
import collections
import itertools
import threading
from cryptography.x509.base import load_der_x509_certificate
from cryptography.x509.base import load_der_x509_csr
from cryptography.hazmat.backends.openssl.x509 import _Certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

LOG_FORMAT = '%(asctime)s [%(process)d] %(levelname)s %(message)s'
logger = logging.getLogger(__name__)
coloredlogs.install(filename='logger.log', level=logging.DEBUG, fmt=LOG_FORMAT)


class MainGUI(object):
    def __init__(self, master):
        self.TabStrip1 = Notebook()
        self.TabStrip1.place(relx=0.062, rely=0.071, relwidth=0.887, relheight=0.9)
        
        ################
        self.TabStrip1__Tab1 = Frame(self.TabStrip1)
        self.FilePathLabel = tkinter.Label(self.TabStrip1__Tab1, text='Chose the target files :', borderwidth=5, font=('',10,'bold'))
        self.FilePathLabel.place(x=30,y=60)
        
        self.FileName = StringVar()
        self.FileName.set('')
        self.FilePathEntry = tkinter.Entry(self.TabStrip1__Tab1, textvariable=self.FileName, state='disabled', borderwidth=4, width=40);
        self.FilePathEntry.place(x=30,y=120)
        
        self.ChoseBut = tkinter.Button(self.TabStrip1__Tab1, text='...', borderwidth=2, command=self.ChoseFile)
        self.ChoseBut.place(x=360,y=118)
        
        self.DetectBut = tkinter.Button(self.TabStrip1__Tab1, text='Detect', font='bold', borderwidth=3, command=self.Detect_file)
        self.DetectBut.place(x=190,y=200)
        
        self.TabStrip1.add(self.TabStrip1__Tab1, text='Single file')
        #################
    
        self.TabStrip1__Tab2 = Frame(self.TabStrip1)
        self.FilePathLabel2 = tkinter.Label(self.TabStrip1__Tab2, text='Chose the directory :', borderwidth=5, font=('',10,'bold'))
        self.FilePathLabel2.place(x=30,y=60)
        
        self.DirName = StringVar()
        self.DirName.set('')
        self.FilePathEntry = tkinter.Entry(self.TabStrip1__Tab2, textvariable=self.DirName, state='disabled', borderwidth=4, width=40);
        self.FilePathEntry.place(x=30,y=120)
        
        self.ChoseBut = tkinter.Button(self.TabStrip1__Tab2, text='...', borderwidth=2, command=self.ChoseDirectory)
        self.ChoseBut.place(x=360,y=118)
        
        self.DetectBut = tkinter.Button(self.TabStrip1__Tab2, text='Detect', font='bold', borderwidth=3, command=self.Detect_dir)
        self.DetectBut.place(x=190,y=200)
        
        self.progress = Progressbar(self.TabStrip1__Tab2, length=200,  mode='indeterminate')
        
        self.TabStrip1.add(self.TabStrip1__Tab2, text='Directory')
        ##################
        
        self.TabStrip1__Tab3 = Frame(self.TabStrip1)
        self.FilePathLabel3 = tkinter.Label(self.TabStrip1__Tab3, text='Your Github login name :', borderwidth=5, font=('',10,'bold'))
        self.FilePathLabel3.place(x=30,y=60)    
        
        self.login_name_Entry = tkinter.Entry(self.TabStrip1__Tab3, borderwidth=4, width=40);
        self.login_name_Entry.place(x=30,y=120)
        
        self.DetectBut = tkinter.Button(self.TabStrip1__Tab3, text='Detect', font='bold', borderwidth=3, command=self.Detect_Github_login_name)
        self.DetectBut.place(x=190,y=200)
        
        self.progress_2 = Progressbar(self.TabStrip1__Tab3, length=200,  mode='indeterminate')
        
        self.TabStrip1.add(self.TabStrip1__Tab3, text='Github account')
        
    def ChoseFile(self):
            
        self.FileName.set(tkinter.filedialog.askopenfilenames())
        
    def ChoseDirectory(self):
        
        self.DirName.set(tkinter.filedialog.askdirectory())
    
    def Detect_file(self):
        start1 = Detector()
        #print self.FileName.get()
        result1 = start1.main(self.FileName.get(),True)
        self.ShowResult(result1)
        return 
        
    def Detect_dir(self):

        def real_traitement():
            self.progress.place(x=135,y=235)
            self.progress.start()
            start2 = Detector()
            result2 = start2.main(self.DirName.get(),False)
            self.progress.stop()
            self.progress.place_forget()
            self.DetectBut['state']='normal'
            self.ShowResult(result2)

        self.DetectBut['state']='disabled'
        threading.Thread(target=real_traitement).start()
        
    def Detect_Github_login_name(self):
        def real_traitement():
            self.progress_2.place(x=135,y=235)
            self.progress_2.start()
            login_name = self.login_name_Entry.get()
            start3 = Detector()
            result3 = start3.process_github(login_name)
            self.progress_2.stop()
            self.progress_2.place_forget()
            self.DetectBut['state']='normal'
            if result3:
                tkinter.messagebox.showwarning("Warning"," SSH keys associated with your account are in danger!")
            elif result3 == False:   
                tkinter.messagebox.showinfo(title = 'Result',message = 'your github account is ok!')
        self.DetectBut['state']='disabled'
        threading.Thread(target=real_traitement).start()        
        
    def ShowResult(self,result):
        """
        process the result of detection and save the result to file(if not None)
        result.txt is created in the same directory with the program
                
        """
        
        if result == None:
            #no vulnerable keys found!
            tkinter.messagebox.showinfo(title = 'Result',message = 'it\'s ok!')
        else:
            #find vulnerable keys and ask for process
            if (tkinter.messagebox.askyesno(title = 'Result',message = 'find vulnerable keys!\n export to file?') == True):
                
                with open('result.txt','w') as f:
                    """ save full path of file and idx to result.txt
                        idx is the order of rsa key in the detected file(for example,'.pem' file have two keys in it sometimes )
                    """
                    f.write('file name\t\t\tidx\n\n')
                    for i,dic in enumerate(result):
                        f.write('%s\t\t\t%d\n'% (dic['fname'],dic['idx']))
                        

class Detector(object):
    """
    to identify formats of files and process respectively    
    """
    def __init__(self):
        self.PEM_num = 0
        self.DER_num = 0
        self.RSA_key_num = 0
        self.SSH_key_num = 0
        self.PGP_num = 0
        self.APK_num = 0
        self.JSON_num = 0
        self.LDIFF_num = 0
        self.JKS_num = 0
        self.PKCS7_num = 0
        self.FileNames = None
        self.Pohlig_hellman = Pohlig_Hellman()
        
    def main(self,FileNames, isfile):
        """
        the entrance of the detection function
        parameters:
            FileNames: the full path of file obtained from MainGUI
            isfile: boolean variable,  file(T) or directory(F)
        return None if no vulnerable keys were found,else return the set of results
        """
        t1 = time.time()
        ret = []
        if FileNames is None:
            return ret
        #print FileNames
        #print type(FileNames)
        find_flag = False
        if isfile:
            FileNames_tuple = tuple(eval(FileNames))
            for file in FileNames_tuple:
                if file.endswith('.tar') or file.endswith('.tar.gz'):
                    result = self.process_tar(file)
                    if result != None:
                        find_flag = True
                        ret.extend(result)        
                    
                else:
                    fh = open(file, 'rb')
                    with fh:
                        data = fh.read()
                    result = self.process_file(data,file)
                    if result != None:
                        find_flag = True
                        ret.extend(result)  
            t2 = time.time()
            logger.info("time use is '%s' seconds\n"% str(t2-t1))                                                
        else:
            return self.process_dir(FileNames)
        if find_flag == True:
            return ret
        else:
            return None
        #return ret
    def process_tar(self, fname):
        """
        process files compressed by 'tar' or 'tar.gz'
        parameters:
            fname: name of compressed files
        return None if no vulnerable keys were found
        """
        
        ret = []
        import tarfile
        find_flag = False
        with tarfile.open(fname) as tar:
            members = tar.getmembers()
            for ti in members:
                if not ti.isfile():
                    continue
                fh = tar.extractfile(ti)
                result = self.process_file(fh.read(),ti.name)
                if result != None:
                    find_flag = True
                    ret.extend(result)
             
        if find_flag == True:
            return ret
        else:
            return None
    
    def process_dir(self, dirname):
        """
        pocess dir iteratively , it can not only process files in the dirname,but also process file in the sub-directory
        parameters:
            dirname: name of directory
        return None if no vulnerable keys were found
        """
        t3 = time.time()
        ret = []
        dir_list = [f for f in os.listdir(dirname)]
        find_flag = False
        for fname in dir_list:
            full_path = os.path.join(dirname, fname)
            if os.path.isfile(full_path):
                with open(full_path, 'rb') as fh:
                    result = self.process_file(fh.read(), fname)
                    if result != None:
                        find_flag = True
                        ret.extend(result)
                    
            elif os.path.isdir(full_path):
                result = self.process_dir(full_path)
                if result != None:
                    ret.extend(result)
                    return ret
        t4 = time.time() 
        logger.info("time use is '%s' seconds\n"% str(t4-t3))
        if find_flag == True:
            return ret
        else:
            return None
        #return ret
    
    def process_file(self, data, fname):
        """
        process 'real' file(neither directory nor compressed),and automatically recognizes the format of files
        parameters:
            data:content of file
            fname:name of file
        """

        if endswith(fname,'.pem') or startswith(data,'-----BEGIN CER') or startswith(data,'-----BEGIN RSA') or startswith(data,'-----BEGIN PUB') or startswith(data,'-----BEGIN PRI'):
            return self.process_pem(data,fname)
        elif endswith(fname,'.pgp') or endswith(fname,'.gpg') or endswith(fname,'.asc') or startswith(data,'-----BEGIN PGP'):
            return self.process_pgp(data,fname)
        elif endswith(fname,'.der') or endswith(fname,'.crt') or endswith(fname,'.cer') or endswith(fname,'.cert'):
            return self.process_der(data,fname)
        elif endswith(fname,'.pub') or startswith(data,'ssh-rsa') or ('ssh-rsa' in data):
            return self.process_ssh(data,fname)
        elif endswith(fname,'.pkcs7') or endswith(fname,'.p7') or endswith(fname,'.p7s') or startswith(data,'-----BEGIN PKCS7'):
            return self.process_pkcs7(data,fname)
        elif endswith(fname,'.apk'):
            return self.process_apk(data,fname)
        else:
            logger.warning("format not supported for '%s'\n"% fname)
            return None
        
        
    def process_pem(self, data, fname):
        """
        process certificate files or rsa key files which are Pem encoded
        Parameters:
            data:content of file
            fname:name of file
        return None if file is safe else report the result 
        """
        ret = []
        find_flag = False
        data = to_string(data)
        parts = re.split(r'-----BEGIN',data)
        if len(parts) == 0:
            return None
        if len(parts[0]) == 0:
            parts.pop(0)
        data_arr = ['-----BEGIN'+ x for x in parts]
        for idx, data_block in enumerate(data_arr):
            data_block = data_block.strip()
            if startswith(data_block,'-----BEGIN CERTIFICATE REQ'):
                result = self.process_pem_certificate_req(data_block,fname,idx)
                if result != None:
                    find_flag = True
                    ret.append(result)
                    
            elif startswith(data_block,'-----BEGIN CERTIFICATE'):
                result = self.process_pem_certificate(data_block,fname,idx)
                if result != None:
                    find_flag = True
                    ret.append(result)
                    
            elif startswith(data_block,'-----BEGIN'):
                result = self.process_pem_rsakeys(data_block,fname,idx)
                if result != None:
                    find_flag = True
                    ret.append(result)
                    
        if find_flag == True:
            return ret
        else:
            return None
        
    def process_pem_certificate_req(self, data, fname, idx):
        """
        process certificate request files(.csr) which are Pem encoded 
        Parameters:
            data:content of file
            fname:name of file
            idx:order of keys in one file
        return None if file is safe else report the result
        """
        try:
            x509_req = load_der_x509_csr(pem_to_der(data), self.get_backend())
            pub_key = x509_req.public_key()
            if not isinstance(pub_key, RSAPublicKey):
                logger.warning("error when process the pem_certificate reqest file '%s'\n"% fname)
                return None
            pub_value = pub_key.public_numbers()
            
            if self.pohlig_hellman_detect(pub_value.n) == True:
                find = collections.OrderedDict()
                find['fname'] = fname
                find['idx'] = idx
                
                return find
            return None 
        except Exception as e:
            logger.error("error when process the pem_certificate request file '%s'\n"% fname)
            return None
            
    def process_pem_certificate(self, data, fname, idx):
        """
        process certificate files  which are Pem encoded
        Parameters:
            data:content of file
            fname:name of file
            idx:order of keys in one file
        return None if file is safe else report the result 
        """
        try:
            x509 = load_der_x509_certificate(pem_to_der(data), self.get_backend())
            pub_key = x509.public_key()
            if not isinstance(pub_key, RSAPublicKey):
                return None
            pub_value = pub_key.public_numbers()
            
            if self.pohlig_hellman_detect(pub_value.n) == True:
                find = collections.OrderedDict()
                find['fname'] = fname
                find['idx'] = idx
                
                return find
            return None 
        except Exception as e:
            logger.error("error when process the pem_certificate file '%s'\n"% fname)
            return None
            
    def process_pem_rsakeys(self, data, fname, idx):
        """
        process rsa key files which are Pem encoded
        Parameters:
            data:content of file
            fname:name of file
            idx:order of keys in one file
        return None if file is safe else report the result 
        """
        try:        
        
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            
            from cryptography.hazmat.primitives.serialization import load_der_private_key
            
            if startswith(data,r'-----BEGIN RSA PUBLIC KEY') or startswith(data,r'-----BEGIN PUBLIC KEY'):
                pub_key = load_der_public_key(pem_to_der(data),self.get_backend())
                pub_value = pub_key.public_numbers()
            elif startswith(data,r'-----BEGIN RSA PRIVATE KEY') or startswith(data,r'-----BEGIN PRIVATE KEY'):
                priv_key = load_der_private_key(pem_to_der(data),None,self.get_backend())
                pub_value = priv_key.private_numbers().public_numbers
                #print pub_value
            if self.pohlig_hellman_detect(pub_value.n) == True:
                find = collections.OrderedDict()
                find['fname'] = fname
                find['idx'] = idx
                
                return find
            return None
        except Exception as e:
            logger.error("error when process the pem_rsakeys file '%s'\n"% fname)
            return None
            
    def process_pgp(self, data, fname):
        """
        process pgp encoded files 
        Parameters:
            data:content of file
            fname:name of file
        return None if file is safe else report the result 
        """
        try:
        
            from pgpdump.data import AsciiData
            from pgpdump.packet import PublicKeyPacket, PublicSubkeyPacket
            ret = []
            data = to_string(data)
            parts = re.split(r'-----BEGIN',data)
            if len(parts) == 0:
                return None
            if len(parts[0]) == 0:
                parts.pop(0)
            data_arr = ['-----BEGIN'+ x for x in parts]
            find_flag = False
            for idx, data_block in enumerate(data_arr):
                data_block = data_block.strip()
                if len(data_block) == 0:
                    continue
                data_block = data_block.encode()
                pgp_key_data = AsciiData(data_block)
                packets = list(pgp_key_data.packets())
                for idy, packet in enumerate(packets):
                    if isinstance(packet, PublicKeyPacket) or isinstance(packet, PublicSubkeyPacket):
                        pub_value = packet
            
                if self.pohlig_hellman_detect(pub_value.modulus) == True:
                    find_flag = True
                    find = collections.OrderedDict()
                    find['fname'] = fname
                    find['idx'] = idx
                    ret.append(find)
        
            if find_flag == True:
                return ret
            else:
                return None
        except Exception as e:
            logger.error("error when process the pgp file '%s'\n"% fname)
            return None  
            
    def process_der(self, data, fname):
        """
        process certificate files which are Der encoded
        Parameters:
            data:content of file
            fname:name of file
        return None if file is safe else report the result 
        """
        try:  
            ret = []
            x509 = load_der_x509_certificate(data, self.get_backend())
            pub_key = x509.public_key()
            if not isinstance(pub_key, RSAPublicKey):
                return
            pub_value = pub_key.public_numbers()
            
            if self.pohlig_hellman_detect(pub_value.n) == True:
                find = collections.OrderedDict()
                find['fname'] = fname
                find['idx'] = 0
                ret.append(find)
                
                return ret
            return None
        except Exception as e:
            logger.error("error when process the der file '%s'\n"% fname)
            return None
            
    def process_ssh(self, data, fname=None):
        """
        process ssh public key files 
        Parameters:
            data:content of file
            fname:name of file
        return None if file is safe else report the result 
        """
        try:
            ret = []
            data = [x.strip() for x in data.split(b'\n')]
            if len(data) > 1:
                if data[1] == '':
                    data.pop(1)
                    
            find_flag = False
            for idx, data_block in enumerate(data):
                
                data_block = data_block[to_bytes(data_block).find(b'ssh-rsa'):]
                if data_block == b'':
                    continue
                ssh_key = load_ssh_public_key(data_block,self.get_backend())
                if not isinstance(ssh_key,RSAPublicKey):
                    continue
                pub_value = ssh_key.public_numbers()
                
                if self.pohlig_hellman_detect(pub_value.n) == True:
                    find_flag = True
                    find = collections.OrderedDict()
                    find['fname'] = fname
                    find['idx'] = idx
                    ret.append(find)
                    
            if find_flag == True:
            
                return ret
            else:
                return None
        except Exception as e:
            logger.error("error when process the ssh file '%s'\n"% fname)
            return None
            
    def process_pkcs7(self, data, fname):
        """
        process PKCS7 signature files with user certificate
        Parameters:
            data:content of file
            fname:name of file
        return None if file is safe else report the result 
        """
        try:
            from cryptography.hazmat.backends.openssl.backend import backend
            ret = []
            if startswith(data,'-----BEGIN'):
                data = data.decode('utf-8')
                data = re.sub(r'\s*-----\s*BEGIN\s+PKCS7\s*-----\s*','',data)
                data = re.sub(r'\s*-----\s*END\s+PKCS7\s*-----\s*','',data)
                der = base64.b64decode(data)
            bio = backend._bytes_to_bio(der)
            pkcs7 = backend._lib.d2i_PKCS7_bio(bio.bio, backend._ffi.NULL)
            backend.openssl_assert(pkcs7 != backend._ffi.NULL)
            signers = backend._lib.PKCS7_get0_signers(pkcs7, backend._ffi.NULL, 0)
            backend.openssl_assert(signers != backend._ffi.NULL)
            backend.openssl_assert(backend._lib.sk_X509_num(signers) > 0)
            x509_ptr = backend._lib.sk_X509_value(signers, 0)
            backend.openssl_assert(x509_ptr != backend._ffi.NULL)
            x509_ptr = backend._ffi.gc(x509_ptr, backend._lib.X509_free)
            x509 = _Certificate(backend, x509_ptr)
            pub_key = x509.public_key()
            if not isinstance(pub_key, RSAPublicKey):
                return
            pub_value = pub_key.public_numbers()
            
            if self.pohlig_hellman_detect(pub_value.n) == True:
                find = collections.OrderedDict()
                find['fname'] = fname
                find['idx'] = 0
                ret.append(find)
                
                return ret
            return None
        except Exception as e:
            logger.error("error when process the pkcs7 file '%s'\n"% fname)
            return None
    
    def process_apk(self, data, fname):
        """
        process android apk files (only supported for python2.*)
        Parameters:
            data:content of file
            fname:name of file
        return None if file is safe else report the result
        """
        #try:
        from apk_parse.apk import APK
        #except:
        #    logger.error("error when import APK, try 'pip install apk_parse_ph4'. If still failed,try 'pip uninstall M2Crypto',then 'sudo apt-get install m2crypto'and retry '%s'\n"% fname)
        #    return None
        ret = []
        apk = APK(data, process_now=False, process_file_types=False, raw=True, temp_dir= '.')
        apk.process()
        pem = apk.cert_pem
        x509 = load_der_x509_certificate(pem_to_der(pem), self.get_backend())
        pub_key = x509.public_key()
        if not isinstance(pub_key, RSAPublicKey):
            return
        pub_value = pub_key.public_numbers()
        
        if self.pohlig_hellman_detect(pub_value.n) == True:
            find = collections.OrderedDict()
            find['fname'] = fname
            find['idx'] = 0
            ret.append(find)
            return ret
        return None
    
    def process_github(self, login_name):
        """
        to test your ssh public keys used in github
        parameters:
            login_name: your GitHub login name
        return True if the account is not safe
        """
        import ssl
        import json
        if sys.version_info[0] == 3:
            import urllib.request as url_lib
        else:
            import urllib2 as url_lib
        ssl._create_default_https_context = ssl._create_unverified_context
        usr_name = login_name
        url = 'https://api.github.com/users/{}/keys'.format(usr_name)
        req = url_lib.Request(url)
        try:
            
            html = url_lib.urlopen(req).read()
        except:
            tkinter.messagebox.showinfo('Not found','SSH keys or login_name not exits')
            return None
            
        html = html.decode('utf-8')
        dict1 = json.loads(html)
        for i in range(0,len(dict1)):
            result = self.process_ssh(dict1[i]['key'], login_name)
            if result != None:
                return True
            
        return False
        
    def get_backend(self, backend=None):
        """
        to return the default crypto backend
        """
        from cryptography.hazmat.backends import default_backend
        return default_backend() if backend is None else backend
    
    def pohlig_hellman_detect(self, num):
        """
        to call the self.Pohlig_hellman.work() and return the result
        parameters:
            num: the public module of RSA
        """
        return self.Pohlig_hellman.work(num)

class Pohlig_Hellman(object):
    """
    The realization of pohlig-hellman algrithm
    """
    def __init__(self):
        self.primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 
                       97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167]
        self.generator = 65537
        self.m,self.phi_m = self.get_phi_m()
        self.largest_prime = 83
        self.phi_m_factorization = self.factorization(self.phi_m,self.largest_prime)
        self.generator_order = self.get_element_order(self.generator,self.m,self.phi_m,self.phi_m_factorization)
        self.generator_order_factorization = self.factorization(self.generator_order,self.largest_prime)
        
    def work(self, N):
        """
        Return true if the public module N is vulnerable
        """
        result = self.discrete_log(N, self.generator, self.generator_order, self.generator_order_factorization, self.m)
        return result 
        
    def get_phi_m(self):
        """
        Return primorial (and its totient), product of all primes below 167
        """
        m = 1
        phi_m = 1
        for i in self.primes:
            m = m*i
            phi_m = phi_m*(i-1)
        return m,phi_m
        
    def factorization(self, num, lim = None):
        """
        Decompose num by small prime factors
        parameters:
            num: the number to be decomposed
            lim: limit of small prime factors
            
        """
        ret = []
        while num % 2 == 0:
            num = num // 2
            ret.append(2)
        while num % 3 == 0:
            num = num // 3
            ret.append(3)
        prime = 5
        i = 2
        while prime <= lim:
            while (num % prime) == 0:
                num = num // prime
                ret.append(prime)
            prime += i
            i = 6-i
        if  num != 1:
            ret.append(num)
        return self.list_to_map(ret)
          
    def list_to_map(self, l):
        """
        Factor list to map factor -> power
        parameters:
            l: the list of small prime factors
        """
        ret = {}
        for k,group in itertools.groupby(l):
            ret[k] = len(list(group))
            
        return ret
        
    def get_element_order(self, element, modulus, phi_m, phi_m_factorization):
        """
        return order of element in multiplicative group
        """
        if pow(element,phi_m,modulus) != 1:
            return None
        order = phi_m
        for (k,power) in phi_m_factorization.items():
            for i in range(1,power+1):
                n_order = order // k
                if pow(element,n_order,modulus) == 1:
                    order = n_order
                else:
                    break
        return order
        
    def discrete_log(self, N, generator, generator_order, generator_order_factorization, modulus):
        """
        the main part of pohlig-hellman algrithm 
        return true if find the solution
        """
        for prime,power in generator_order_factorization.items():
            find = 0
            pri_to_power = prime ** power
            order_div_primepower = generator_order // pri_to_power
            temp_1 = pow(N,order_div_primepower,modulus)
            temp_2 = pow(generator,order_div_primepower,modulus)
            for i in range(0,pri_to_power):
                if pow(temp_2,i,modulus) == temp_1:
                    find = 1
                    break
            if find == 0:
                return False
        return True
        
def to_string(data):
    """
    convert to basestring
    """
    if isinstance(data,bytes):
        return data.decode('utf-8')
    if isinstance(data,basestring):
        return data

def to_bytes(data):
    """
    convert to bytes
    """
    if isinstance(data,bytes):
        return data
    if isinstance(data,basestring):
        return data.encode('utf-8')
        
def startswith(data, string):
    """
    redefinition of str.startswith() to avoid conflict result from version
    """
    if data is None:
        return False

    if sys.version_info[0] < 3:
        return data.startswith(string)

    return to_bytes(data).startswith(to_bytes(string))

def endswith(data, string):
    """
    redefinition of str.endswith() to avoid conflict result from version
    """
    if data is None:
        return False

    if sys.version_info[0] < 3:
        return data.endswith(string)

    return to_bytes(data).endswith(to_bytes(string))

def pem_to_der(data):
    """
    convert content of file Pem encoded to Der encoded
    """
    data = re.sub(r'-----BEGIN .+-----','',data)
    data = re.sub(r'-----END .+-----','',data)
    data = data.replace(' ','')
    data = data.replace('\n','')
    data = data.replace('\t','')
    data = data.replace('\r','')
    return base64.b64decode(data)
    
def main():
    main = tkinter.Tk()
    main.title('Vulnerable keys detector')
    main.geometry('500x320')
    mypro = MainGUI(main)
    tkinter.mainloop()
if __name__ == '__main__':
    main()
    