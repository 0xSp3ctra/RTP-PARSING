from netifaces import interfaces
from pyshark import LiveCapture
from console import getTerminalSize
from os import system
from re import search
from datetime import datetime

# BLACK
# PRE-COMMIT
# https://pypi.org/project/g711/

clean=True # only leave the last merged wave file
clean=False # only leave the last merged wave file

sizex = getTerminalSize()[0]
CID='undefined'
fs=8000
started=False
m = 4 # margin
PileAssignment={}
SIP1=0
SIP2=0

class Pile:
    def __init__(self,ip):
        self.list=[]
        self.t=None
        self.ip=ip
    def add(self,p):
        """:param p: packet object"""
        if not self.list:self.t=p.time
        self.list.insert(int((p.time-self.t)/160),p.data)
        return 1
    def write(self):
        with open(f'{self.ip}.g711u','wb') as f:
            for rtp in self.list:f.write(bytearray.fromhex(" ".join(rtp)))

class Packet:
    def __init__(self,p):
        global CID,fs,SIP1,SIP2
        self.sip=None if not hasattr(p,'sip') else p.sip._all_fields
        self.rtp=None if self.sip or not hasattr(p,'rtp') else p.rtp._all_fields
        self.ip=p['IP'].dst
        del p
        # SIP info
        self.method=None if self.rtp or (not self.sip) or (not 'sip.Method' in self.sip) else self.sip['sip.Method']
        a=list(self.sip.values())[0].replace('SIP/2.0 ','').replace('SIP/2.0','')[0]
        self.desc='' if not self.sip else (' '*m+('{:->'+str(sizex-m*2)+'}' if a.isdigit() else '{}')+'\n').format(a)
        del a
        self.isok=None if (not self.sip) or self.method else self.sip['sip.Status-Code']=='200'
        # RTP info
        self.time=None if not self.rtp else int(self.rtp['rtp.timestamp'])
        self.data=None if not (self.rtp or 'rtp.payload' in self.rtp) else self.rtp['rtp.payload'].split(":")
        # GLOBALS
        if CID=='undefined':CID=None if not self.sip else self.sip['sip.Call-ID']
        a=None if self.method!='INVITE' else search(r"telephone-event/([0-9])\w+",self.sip['sip.msg_hdr']).group().split('/')[1]
        if not SIP1:SIP1=None if not a else self.sip['sip.from.user']
        if not SIP2:SIP2=None if not self.SIP1 else self.sip['sip.to.user']
        if a:fs=a
        del a

print('''
Created by Breee and Spectra
21/06/2022

  ██████  ██▓███ ▓██   ██▓    ▄████▄   ▄▄▄       ██▓     ██▓    
▒██    ▒ ▓██░  ██▒▒██  ██▒   ▒██▀ ▀█  ▒████▄    ▓██▒    ▓██▒    
░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░   ▒▓█    ▄ ▒██  ▀█▄  ▒██░    ▒██░    
  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░   ▒▓▓▄ ▄██▒░██▄▄▄▄██ ▒██░    ▒██░    
▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░   ▒ ▓███▀ ░ ▓█   ▓██▒░██████▒░██████▒
▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒    ░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░▓  ░░ ▒░▓  ░
░ ░▒  ░ ░░▒ ░     ▓██ ░▒░      ░  ▒     ▒   ▒▒ ░░ ░ ▒  ░░ ░ ▒  ░
░  ░  ░  ░░       ▒ ▒ ░░     ░          ░   ▒     ░ ░     ░ ░   
      ░           ░ ░        ░ ░            ░  ░    ░  ░    ░  ░
                  ░ ░        ░                                  
'''
)


print(interfaces)
capture = LiveCapture(interface=input("Nom de l'interface: "), display_filter='sip or rtp')
# print(capture.set_debug())
format='%d/%m/%Y %H:%M:%S'
start=datetime.now().strftime(format)
for packet in capture.sniff_continuously():
    p=Packet(packet)
    if p.ip!='192.168.0.100':
        #print(vars(p))
        print(p.desc,end='')
        if p.ip and p.data:
            if not p.ip in PileAssignment:PileAssignment[p.ip]=Pile(p.ip)
            if PileAssignment[p.ip].add(p) and not started:
                started=True
                print(' '*m+('{:█^'+str(sizex-m*2)+'}').format(' CALL STARTED '))
    if p.method=='BYE':break
end=datetime.now().strftime(format)
# PileAssignment['blabla']=Pile('ip')
# PileAssignment['blabla'].list=['ok']
# print(all(list(a.list for a in PileAssignment.values())))
# PileAssignment=False
for key in PileAssignment:
    if not PileAssignment[key].list:del PileAssignment[key]
if PileAssignment and all(list(a.list for a in PileAssignment.values())):
    from sys import platform
    from os import remove,listdir
    if platform=='win32':
        for ip in PileAssignment:PileAssignment[ip].write()
        from subprocess import call
        with open('temp.bat','w') as f:f.write('set PATH="C:\\Program Files (x86)\\sox-14-4-2"\nsox --type raw --rate 8000 -e u-law %1.g711u %1.wav\nsox --type raw --rate 8000 -e u-law %2.g711u %2.wav\nsox -M %1.wav %2.wav %3.wav')
        ips=list(ip for ip in PileAssignment)
        call(['temp.bat',ips[0],ips[1],CID])
        remove("temp.bat")
    else:
        cmd='sox -'+('M' if len(PileAssignment)==2 else 'm')
        for ip in PileAssignment:
            PileAssignment[ip].write()
            system(f'sox --type raw --rate {fs} -e u-law {ip}.g711u {ip}.wav')
            cmd+=f' {ip}.wav'
        cmd+=f' {CID}.wav'
        system(cmd)
    if clean:
        for item in listdir():
            if search(r"^(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})){3}.*",item).group().split('/')[1]:remove(item)

with open('infos_call.txt', 'w') as f:f.write("{} --> {}\nDate de début : {: >}\nDate de fin :   {: >}\nCall ID :       {}".format(SIP1,SIP2,start,end,CID))
