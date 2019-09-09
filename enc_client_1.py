#!/usr/bin/python

# Encryption Client for CS 352 
# (c) 2018, R. P. Martin, under GPL Version 2

# this client opens a text files, and send the lines one at a time to a remote echo
# server, and makes sure the MD5 checksum of all the lines sent matches the lines received
# this server encrypts the data use the Python Sodium library 

import argparse
import time
import struct 
import md5
import os 
import sock352

def main():
    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 Socket Client')
    parser.add_argument('-f','--filename', help='File to Echo', required=False)
    parser.add_argument('-d','--destination', help='Destination IP Host', required=True)
    parser.add_argument('-p','--remoteport', help='remote sock352 UDP port', required=False)
    parser.add_argument('-k','--keychain', help='keychain file', required=True)
    parser.add_argument('-l','--localport', help='local sock352 UDP port', required=True)
    parser.add_argument('-x','--debuglevel', help='Debug Level')
    parser.add_argument('-z','--dropprob', help='Drop Probability')

    
    # get the arguments into local variables
    debug_level = 0 
    args = vars(parser.parse_args())
    filename = args['filename']
    destinationIP = args['destination']
    remote_port = args['remoteport']
    local_port =  args['localport']
    keychain_file =  args['keychain']
    
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
            
    # set the debug level in the library
    s.set_random_seed(352)
    s.set_debug_level(debug_level)
    s.set_drop_prob(probability)

    dest_addr = (destinationIP,int(remote_port))
    
    # use the MD5 hash algorithm to validate all the data is correct
    mdhash_sent = md5.new()
    mdhash_recv = md5.new()
    # a lines of lines to echo back 
    lines = fd.readlines()
    rtt_times = []
    
    # for each line, take a time-stamp, send and recive the line, update the list of RTT times,
    # and then update the MD5 hash of the sent and received data
    
    zero_stamp = time.clock()
    s.connect(dest_addr)

    num_lines = str(len(lines))
    s.sendto(num_lines)
    line_number = int(num_lines)
    for line in lines:
        start_stamp = time.clock()
        if (debug_level > 0):
            print "rel_client -- sending line %d: %s" % (line_number,line)
        send = s.sendto(line)
        recv_data = s.recvfrom(len(line))
        end_stamp = time.clock() 
        lapsed_seconds = float(end_stamp - start_stamp)
        rtt_times.append(lapsed_seconds) 
        line_number = line_number - 1
        # update the sent and received data 
        mdhash_sent.update(line)
        mdhash_recv.update(recv_data)        

    # this allows use to time the entire loop, not just every RTT
    # Allows estimation of the protocol delays
    s.close()
    final_stamp = end_stamp 

    # this part send the lenght of the digest, then the
    # digest. It will be check on the server 
    digest_sent = mdhash_sent.digest()
    digest_recv = mdhash_recv.digest()

    
    # compute RTT statisticis
    rtt_min = min(rtt_times)
    rtt_max = max(rtt_times)
    rtt_ave = float(sum(rtt_times)) / float(len(rtt_times))
    total_time = final_stamp - zero_stamp                                           
                                           
    print ("rel_client: echoed %d messages in %0.6f millisec min/max/ave RTT(msec) %.4f/%.4f/%.4f " %
           (len(lines), total_time*1000, rtt_min*1000,rtt_max*1000,rtt_ave*1000))


    # compare the two digests, byte for byte
    failed = False;
    for i, sent_byte in enumerate(digest_sent):
        recv_byte = digest_recv[i]
        if (sent_byte != recv_byte):
            print( "rel_client: digest failed at byte %d diff: %c %c " % (i,sent_byte,recv_byte))
            failed = True;
    if (not failed):
        print( "echo_client: digest succeeded")
    
    fd.close()
                                           
# this gives a main function in Python
if __name__ == "__main__":
    main()
# last line of the file 
