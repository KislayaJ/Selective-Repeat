#!/usr/bin/python

# Encryption bandwidth test for CS 352 
# (c) 2018, R. P. Martin, under GPL Version 2

# this program opens a file, and sends blocks of data one at a time.
# server, and makes sure the MD5 checksum of all the lines sent matches the lines received

import argparse
import time
import struct 
import md5
import os
import sys
import binascii
import sock352


def main():
    # parse all the arguments to the client
    if (sys.argv[0]): 
        prog_name = sys.argv[0]
    else:
        prog_name = 'rel_bw_test.py'

        
    parser = argparse.ArgumentParser(description='CS 352 Socket Client')
    parser.add_argument('-f','--filename', help='File to Echo', required=False)
    parser.add_argument('-d','--destination', help='Destination IP Host', required=True)
    parser.add_argument('-p','--remoteport', help='Remote sock352 UDP port', required=False)
    parser.add_argument('-k','--keychain', help='keychain file', required=True)
    parser.add_argument('-l','--localport', help='Local sock352 UDP port', required=True)
    parser.add_argument('-s','--server', help='Run as server', action='store_true')
    parser.add_argument('-x','--debuglevel', help='Debug Level')
    parser.add_argument('-z','--dropprob', help='Drop Probability')
        
    # get the arguments into local variables 
    args = vars(parser.parse_args())
    filename = args['filename']
    destinationIP = args['destination']
    remote_port = args['remoteport']
    local_port =  int(args['localport'])
    keychain_file =  args['keychain']
    run_as_server = args['server']


    # set the debug level. 0 = no debug statements, 10 = maximum debug output 
    if (args['debuglevel'] == None):
        debug_level = 0
    else:
        debug_level =  int(args['debuglevel'])


    # set the drop probability. 0.0 = no data drops, 1.0 = drop everything 
    if (args['dropprob'] == None):
        probability =  0.0
    else:
        probability =  float(args['dropprob'])

    # open the file for reading
    if (filename):
        try: 
            filesize = os.path.getsize(filename)
            fd = open(filename, "rb")
        except:
            print ( "error opening file: %s" % (filename))
            exit(-1)
    else:
        pass 

    # create a socket and connect to the remote server
    s = sock352.Socket()

    # read the keychain file 
    s.readKeyChain(keychain_file)

    dest_addr = (destinationIP,int(remote_port))
    
    # use the MD5 hash algorithm to validate all the data is correct
    mdhash_sent = md5.new()
    mdhash_recv = md5.new()
    # a lines of lines to echo back
    
    # for each line, take a time-stamp, send and recive the line, update the list of RTT times,
    # and then update the MD5 hash of the sent and received data

    # the maximum packet size for this transfer is 4K
    max_pkt_size = (4*1024)
    # set the debug level in the library
    s.set_random_seed(352)
    s.set_debug_level(debug_level)
    s.set_drop_prob(probability)
    
    # start time stamp to compute the bandwidth 
    start_stamp = time.time()

    # run as a client or server 
    if (run_as_server):
        s.bind(('', local_port))
        from_addr = s.accept()
    else:
        s.connect(dest_addr)
    
    # the first message is the file size to send 
    bytes_to_send = filesize
    send = s.sendto(str(bytes_to_send))

    # how many bytes to receive from the remote side
    recv_size = int(s.recvfrom(max_pkt_size))
    # this is the downcounter 
    bytes_to_receive = recv_size

    total_bytes = filesize + recv_size
    
    print ("%s: sending %d bytes, receiving %d bytes " % (prog_name,bytes_to_send, bytes_to_receive))
    
    # loop until there are no bytes left to send or receive
    i = 0 
    while ( (bytes_to_send > 0) or (bytes_to_receive > 0) ):

        if (bytes_to_send >0):        
            if (bytes_to_send >= max_pkt_size):
                size_to_send = max_pkt_size 
            else:
                size_to_send = bytes_to_send
                
            send_data = fd.read(size_to_send)     
            send = s.sendto(send_data)
            bytes_to_send = bytes_to_send - size_to_send
            mdhash_sent.update(send_data)
            i = i +1
            if ((i % 100) == 0 ):
                print ".",
                
        if (bytes_to_receive > 0):
            recv_data = s.recvfrom(max_pkt_size)
            bytes_to_receive = bytes_to_receive - len(recv_data)
            mdhash_recv.update(recv_data)                    

    print " "
    digest_sent = mdhash_sent.digest()
    digest_recv = mdhash_recv.digest()

    send = s.sendto(digest_recv)
    remote_digest = s.recvfrom(max_pkt_size)

    s.close()            
    end_stamp = time.time()
    lapsed_seconds = float(end_stamp - start_stamp)
    fd.close()

    print "rel: sent digest: x%s received digest x%s remote digest x%s " % (binascii.hexlify(digest_sent), binascii.hexlify(digest_recv), binascii.hexlify(remote_digest))

    # this part send the lenght of the digest, then the
    # digest. It will be check on the server 

    # compute bandwidthstatisticis
    total_time = end_stamp - start_stamp

    # slight hack to make the total_time a positive epsilon 
    if (total_time == 0.0):
        total_time = 0.0000000001
        
    bandwidth = (float(total_bytes)/ total_time)/1000000.0

    # make sure the digest from the remote side matches what we sent
    failed = False;
    for i, sent_byte in enumerate(digest_sent):
        remote_byte = remote_digest[i]
        if (sent_byte != remote_byte):
            print( "%s: digest failed at byte %d diff: %c %c " % (prog_name,i,sent_byte,remote_byte))
            failed = True;
    if (not failed):
        print( "%s: digest succeeded bandwidth %f Mbytes/sec" % (prog_name,bandwidth) )

    # this makes sure all threads exit 
    os._exit(1)
    
# create a main function in Python
if __name__ == "__main__":
    main()
