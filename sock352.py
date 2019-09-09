# sock352.py 

# (C) 2018 by R. P. Martin, under the GPL license, version 2.

# this is the skeleton code that defines the methods for the sock352 socket library, 
# which implements a reliable, ordered packet stream using go-back-N.
#
# Note that simultaneous close() is required, does not support half-open connections ---
# that is outstanding data if one side closes a connection and continues to send data,
# or if one side does not close a connection the protocol will fail. 

import socket as ip
import random
import binascii
import threading
import time
import sys
import struct as st
import os
import signal

# additional imports for the nacl library 
from inspect import currentframe, getframeinfo
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# The first byte of every packet must have this value 
MESSAGE_TYPE = 0x45

# this defines the sock352 packet format.
# ! = big endian, b = byte, L = long, H = half word
HEADER_FMT = '!bbLLH'

# this are the flags for the packet header 
SYN =  0x01    # synchronize 
ACK =  0x02    # ACK is valid 
DATA = 0x04    # Data is valid 
FIN =  0x08    # FIN = remote side called close 

# max size of the data payload is 63 KB
MAX_SIZE = (63*1024)

# max size of the packet with the headers 
MAX_PKT = ((16+16+16)+(MAX_SIZE))

# these are the socket states 
STATE_INIT = 1
STATE_SYNSENT = 2
STATE_LISTEN  = 3
STATE_SYNRECV = 4 
STATE_ESTABLISHED = 5
STATE_CLOSING =  6
STATE_CLOSED =   7
STATE_REMOTE_CLOSED = 8


list_of_all_sockets=[]

# function to print. Higher debug levels are more detail
# highly recommended 
def dbg_print(level,string):
    global sock352_dbg_level 
    if (sock352_dbg_level >=  level):
        print string 

# this is the thread object that re-transmits the packets 
class sock352Thread (threading.Thread):
    
    def __init__(self, threadID, name, delay):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.delay = float(delay)
        
    def run(self):
        dbg_print(3,("sock352: timeout thread starting %s delay %.3f " % (self.name,self.delay)) )
        scan_for_timeouts(self.delay)
        dbg_print(3,("sock352: timeout thread %s Exiting " % (self.name)))      
# Example timeout thread function
# every <delay> seconds it wakes up and re-transmits packets that
# have been sent, but not received. A received packet with a matching ack
# is removed from the list of outstanding packets.

def scan_for_timeouts(delay):
    global list_of_all_sockets
    time.sleep(delay)
    timeoutCnt = len(list_of_all_sockets) > 0
    # there is a global socket list, although only 1 socket is supported for now 
    while timeoutCnt:

        time.sleep(delay)
        dbg_print(1, 'sock352: Scanning for timeouts')
        # example 
        for sock in list_of_all_sockets: 
            pktDets = sock.sent_sk_buffs
            for pktDetails in pktDets:
                current_time = time.time()
                time_diff = float(current_time) - float(pktDetails.transmissionTime)
                if time_diff > delay:
                    sock.transmit(pktDetails)
        timeoutCnt = len(list_of_all_sockets) > 0


# This class holds the data of a packet gets sent over the channel 
# 
class Packet:
    def __init__(self):
        self.type = MESSAGE_TYPE    # ID of sock352 packet
        self.cntl = 0               # control bits/flags 
        self.seq = 0                # sequence number 
        self.ack = 0                # acknowledgement number 
        self.size = 0               # size of the data payload 
        self.data = ''             # data 

    # unpack a binary byte array into the Python fields of the packet 
    def unpack(self,bytes):
        # check that the data length is at least the size of a packet header 
        data_len = (len(bytes) - st.calcsize('!bbLLH'))
        if (data_len >= 0): 
            new_format = HEADER_FMT + str(data_len) + 's'
            values = st.unpack(new_format,bytes)
            self.type = values[0]
            self.cntl = values[1]
            self.seq  = values[2]
            self.ack  = values[3]
            self.size = values[4] 
            self.data = values[5]
            # you dont have to have to implement the the dbg_print function, but its highly recommended 
            dbg_print (1,("sock352: unpacked:0x%x cntl:0x%x seq:0x%x ack:0x%x size:0x%x data:x%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data))))
        else:
            dbg_print (2,("sock352 error: bytes to packet unpacker are too short len %d %d " % (len(bytes), st.calcsize('!bbLLH'))))

        return
    
    # returns a byte array from the Python fields in a packet 
    def pack(self):
        if (self.data == None): 
            data_len = 0
        else:
            data_len = len(self.data)
        if (data_len == 0):
            bytes = st.pack('!bbLLH',self.type,self.cntl,self.seq,self.ack,self.size)
        else:
            new_format = HEADER_FMT + str(data_len) + 's'  # create a new string '!bbLLH30s' 
            dbg_print(5,("cs352 pack: %d %d %d %d %d %s " % (self.type,self.cntl,self.seq,self.ack,self.size,self.data)))
            bytes = st.pack(new_format,self.type,self.cntl,self.seq,self.ack,self.size,self.data)
        return bytes
    
    # this converts the fields in the packet into hexadecimal numbers 
    def toHexFields(self):
        if (self.data == None):
            retstr=  ("type:x%x cntl:x%x seq:x%x ack:x%x sizex:%x" % (self.type,self.cntl,self.seq,self.ack,self.size))
        else:
            retstr= ("type:x%x cntl:x%x seq:x%x ack:x%x size:x%x data:x%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data)))
        return retstr

    # this converts the whole packet into a single hexidecimal byte string (one hex digit per byte)
    def toHex(self):
        if (self.data == None):
            retstr=  ("%x%x%x%xx%x" % (self.type,self.cntl,self.seq,self.ack,self.size))
        else:
            retstr= ("%x%x%x%x%xx%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data)))
        return retstr


# the main socket class
# you must fill in all the methods
# it must work against the class client and servers
# with various drop rates

class sk_buff():

    def __init__(self,socket,packet):
        self.packet = packet
        self.sock = socket
        self.transmissionTime = 0.0

class Socket:

    def __init__(self):

        self.state = STATE_INIT
        self.to_addr = ('',0)
        self.frm_addr = ('',0)
        self.rem_close = 0
        self.window = 1
        self.sent_sk_buffs = []
        self.received_sk_buffs = []
        self.seq_no = random.randint(0,65535)
        self.sock = ip.socket(ip.AF_INET, ip.SOCK_DGRAM)
        self.drop_prob = 0.0
        self.random_seed = 0
        self.privateKeys = {}
        self.privateKeysHex = {}
        self.publicKeys = {}
        self.publicKeysHex = {} 
        list_of_all_sockets.append(self)



    # Read the key chain file. The result should be a private key and a keychain of
    # public keys
    def readKeyChain(self,filename):
        if (filename):
            try:
                keyfile_fd = open(filename,"r")
                for line in keyfile_fd:
                    words = line.split()
                    # check if a comment
                    # more than 2 words, and the first word does not have a
                    # hash, we may have a valid host/key pair in the keychain
                    if ( (len(words) >= 4) and (words[0].find("#") == -1)):
                        host = words[1]
                        port = words[2]
                        keyInHex = words[3]
                        if (words[0].lower() == "private"):
                            self.privateKeysHex[(host,port)] = keyInHex
                            self.privateKeys[(host,port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                        elif (words[0].lower() == "public"):
                            self.publicKeysHex[(host,port)] = keyInHex
                            self.publicKeys[(host,port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
            except Exception,e:
                print ( "error: opening keychain file: %s %s" % (filename,repr(e)))
        else:
            print ("error: No filename presented")             

        return (self.publicKeys,self.privateKeys)


    # Print a debugging statement line
    # 
    # 0 == no debugging, greater numbers are more detail.
    # You do not need to implement the body of this method,
    # but it must be in the library.
    def set_debug_level(self, level):
        global sock352_dbg_level
        if (level>=0 and level <=10):
            sock352_dbg_level = level
        else:
            print 'sock352: Invalid debug level entered. (0-10)'
            sock352_dbg_level = 0

    # Set the % likelihood to drop a packet
    #
    # you do not need to implement the body of this method,
    # but it must be in the library,
    def set_drop_prob(self, probability):
        if probability >= 0.0 or probability <= 1.0:
            self.drop_prob = probability
        else:
            print 'sock352: invalid probability require [0.0-1.0]'
            self.drop_prob = 0.0

    # Set the seed for the random number generator to get
    # a consistent set of random numbers
    # 
    # You do not need to implement the body of this method,
    # but it must be in the library.
    def set_random_seed(self, seed):
        self.random_seed = seed 
        

    # bind the address to a port
    # You must implement this method
    def transmit(self, pktDet):
        address = self.to_addr
        pkt = pktDet.packet
        bytes = pkt.pack()
        dbg_print(1, 'sock352: transmit: packet: %s ' % pkt.toHexFields())
        retVal = self.sock.sendto(bytes, address)
        pktDet.transmissionTime = time.time()
        return retVal

    def ackSend(self, pckt, flag):
        addr = self.to_addr
        pkt = Packet()
        pkt.type = MESSAGE_TYPE
        pkt.cntl = flag
        pkt.seq = 0
        pkt.ack = pckt.seq
        pkt.size = 0
        pkt.data = None
        pkt_Sk_buff = sk_buff(self, pkt)
        self.transmit(pkt_Sk_buff)

    def cleanup_transmit_queue(self, pkt):
        if pkt.cntl & ACK == ACK:
            for i in range (len(self.sent_sk_buffs)):
                skb = self.sent_sk_buffs[i]
                if skb.packet.seq == pkt.ack:
                    del self.sent_sk_buffs[i]
                    break
        else:
            dbg_print(3, 'sock352: cleanup called on non-ack packet')


    def bind(self,address):
        self.frm_addr = address
        return self.sock.bind(address)

    # connect to a remote port
    # You must implement this method
    def connect(self,address):
        self.to_addr = address
        self.connection_key = None
        for key in self.publicKeys.keys():
            key_addr = key[0]
            key_host = key[1]
            if key_addr == address[0]:
                if key_host =='*':
                    self.connection_key = self.publicKeys[key]
                    break
                else:
                    key_host = int(key_host)
                    if int(key_host) == address[1]:
                        self.connection_key = self.publicKeys[key]
                        break
        if self.connection_key == None:
            print 'No connection key found'
            raise ip.error
        self.nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        self.box = Box(self.privateKeys[('*', '*')], self.connection_key)
        connectPkt = Packet()
        connectPkt.type = MESSAGE_TYPE
        connectPkt.cntl = SYN
        connectPkt.seq = self.seq_no
        connectPkt.ack = 0
        connectPkt.size = 0
        connectPkt.data = ''
        connectPktDetails = sk_buff(self, connectPkt)
        self.sent_sk_buffs.append(connectPktDetails)
        self.transmit(connectPktDetails)
        self.state = STATE_SYNSENT

        while self.state == STATE_SYNSENT:
            data, addr = self.sock.recvfrom(MAX_SIZE)
            newPkt = Packet()
            newPkt.unpack(data)
            if newPkt.cntl != SYN | ACK:
                self.transmit(newPackDet)
                continue
            if newPkt.ack == self.seq_no:
                self.cleanup_transmit_queue(newPkt)
                self.ackSend(newPkt,ACK)
                self.next_recv = newPkt.seq + 1
                self.state = STATE_ESTABLISHED
            else:
                self.transmit(newPackDet)


    #accept a connection
    def accept(self):
        self.state = STATE_LISTEN
        self.seq = 39201
        while self.state == STATE_LISTEN:
            data, frm_addr = self.sock.recvfrom(MAX_SIZE)
            pkt = Packet()
            pkt.unpack(data)
            if pkt.type != MESSAGE_TYPE:
                dbg_print(1, 'wrong packet type')
                continue
            if pkt.cntl != SYN:
                dbg_print(1, 'SYN not set.')
                continue
            self.to_addr = frm_addr
            self.accept_key = None
            for key in self.publicKeys.keys():
                key_addr = key[0]
                key_host = key[1]
                if key_addr == frm_addr[0]:
                    if key_host =='*':
                        self.accept_key = self.publicKeys[key]
                        break
                    else:
                        key_host = int(key_host)
                        if int(key_host) == frm_addr[1]:
                            self.accept_key = self.publicKeys[key]
                            break
            if self.accept_key == None:
                print 'Could not find acceptance key'
            self.next_recv = pkt.seq
            ackPkt = Packet()
            ackPkt.type = MESSAGE_TYPE
            ackPkt.cntl = SYN | ACK
            ackPkt.seq = self.seq_no
            ackPkt.ack = self.next_recv = pkt.seq
            ackPkt.data = None
            ackPktDet = sk_buff(self,ackPkt)
            self.sent_sk_buffs.append(ackPktDet)
            self.transmit(ackPktDet)
            self.state = STATE_SYNRECV
            self.next_recv = pkt.seq + 1
            self.nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
            self.box = Box(self.privateKeys[('*', '*')], self.accept_key)

            return frm_addr




    
    # send a message up to MAX_DATA
    # You must implement this method     
    def sendto(self,buffer):
        pkt = Packet()
        pkt.type = MESSAGE_TYPE
        pkt.cntl = DATA
        self.seq_no = self.seq_no + 1
        pkt.seq = self.seq_no
        if buffer == None:
            pkt.size = 0
            pkt.data = None
        else:
            encrypted = self.box.encrypt(buffer, self.nonce)
            pkt.data = encrypted
            pkt.size = len(encrypted)
        newPackDet = sk_buff(self, pkt)
        self.sent_sk_buffs.append(newPackDet)
        return self.transmit(newPackDet)

    # receive a message up to MAX_DATA
    # You must implement this method     
    def recvfrom(self,nbytes):
        isData = False
        while isData == False:
            if len(self.received_sk_buffs) > 0:
                if self.received_sk_buffs[0].packet.seq + 1 == self.next_recv:
                    newPackDet = self.received_sk_buffs.pop(0)
                    pkt = newPackDet.packet
                    address = newPackDet.frm_addr
            else:
                payload, address = self.sock.recvfrom(MAX_SIZE) 
                pkt = Packet()
                pkt.unpack(payload)
            if (pkt.type != MESSAGE_TYPE):
                dbg_print(4, 'sock352: Incorrect packet type')
                isData = False
                continue
            if (self.state ==STATE_ESTABLISHED or self.state == STATE_CLOSING or self.state == STATE_SYNRECV):
                if (pkt.cntl & ACK == ACK):
                    self.cleanup_transmit_queue(pkt)
                    if (pkt.cntl == ACK and pkt.size == 0):
                        if self.state == STATE_CLOSING:
                            return None
                        isData = False
                        continue
                if (pkt.cntl & DATA == DATA):
                    if (self.drop_prob > 0.0):
                        num = random.random()
                        if (num<= self.drop_prob):
                            isData = False
                            continue
                    if (pkt.seq == self.next_recv):
                        self.next_recv = self.next_recv + 1
                        self.ackSend(pkt, ACK)
                        decrypted = self.box.decrypt(pkt.data)
                        if len(decrypted) > nbytes:
                            return decrypted[0:nbytes]
                        else:
                            return decrypted

                    else:
                        base = self.seq_no + 1
                        if (pkt.seq > base and pkt.seq_no < base + self.window):
                            found = False
                            for newPackDet in self.received_sk_buffs:
                                if newPackDet.packet.seq == pkt.seq:
                                    found = True
                                    break
                            if found == False:
                                fin_pkt_det = sk_buff(self, pkt)
                                self.ackSend(pkt,ACK)
                                self.received_sk_buffs.append(fin_pkt_det)
                            else:
                                dbg_print(6, 'sock352: duplicate packet recieved in recieve list')
                    
                if pkt.cntl & FIN == FIN:
                    self.rem_close = STATE_REMOTE_CLOSED
                    self.ackSend(pkt,ACK)
                    if self.state == STATE_CLOSING:
                        isData = False
                        return None
                    isData = False
                    continue
                if pkt.cntl & SYN == SYN:
                    isData = False
                    continue
                else:
                    dbg_print(1,'Unknown control bit in packet')
                    isData = False
                    continue
            else:
                dbg_print(3, 'Unknown socket state')

            print 'Recvfrom done'

    # close the socket and make sure all outstanding
    # data is delivered 
    # You must implement this method         
    def close(self):
        self.seq_no = self.seq_no + 1
        pkt = Packet()
        pkt.type = MESSAGE_TYPE
        pkt.cntl = FIN
        pkt.seq = self.seq_no
        pkt.ack = 0
        pkt.size = 0
        pkt.data = None
        newPackDet = sk_buff(self, pkt)
        self.sent_sk_buffs.append(newPackDet)
        self.transmit(newPackDet)
        self.state = STATE_CLOSING
        pktDetNum = len(self.sent_sk_buffs)
        count = 0
        while (pktDetNum > 1):
            data = self.recvfrom(MAX_SIZE)
            pktDetNum = len(self.sent_sk_buffs)
            time.sleep(0.25)
            count += 1
        while (self.rem_close != STATE_REMOTE_CLOSED):
            data = self.recvfrom(MAX_SIZE)
            time.sleep(0.5)

        
# Example how to start a start the timeout thread
global sock352_dbg_level 
sock352_dbg_level = 0
dbg_print(3,"starting timeout thread")

# create the thread 
thread1 = sock352Thread(1, "Thread-1", 0.25)

# you must make it a daemon thread so that the thread will
# exit when the main thread does. 
thread1.daemon = True

# run the thread 
thread1.start()


