import re
import socket
import struct
import sys
from hashlib import md5
from time import time, sleep

VERSION = "1.1"

# Errors:
#   0x1000 block: Authentication errors
#   0x2000 block: Unused (probably for MSServer parsing errors?)
#   0x4000 block: File errors
#   0x8000 block: Socket errors
#
# Detailed Error List:
#   0x1001: Master server did not approve challenge response
#   0x1002: Master server did not verify CD key
#   0x1003: CD key not in recognized format
#
#   0x4001: Failed to open file for reading
#   0x4002: Failed to open file for writing
#
#   0x8001: Connection timed out
#   0x8002: Attempt to use a closed socket
#   0x8003: Attempt to read unreasonable amount of data, socket closed as result
#   0x8004: Attempt to use socket that was never opened
#   0x8005: Something else happened when using a socket

E_AUTH = 0x1000
E_FILE = 0x4000
E_SOCK = 0x8000

E_APPROVE_FAILURE = 0x1001
E_VERIFY_FAILURE = 0x1002
E_BAD_CDKEY = 0x1003

E_READ_FAILURE = 0x4001
E_WRITE_FAILURE = 0x4002

E_TIMED_OUT = 0x8001
E_SOCKET_CLOSED = 0x8002
E_LENGTH_OVERFLOW = 0x8003
E_SOCKET_NOT_OPEN = 0x8004
E_SOCKET_FAILURE = 0x8005

################################################################################
# Class Definitions

class MSConnection(object):
    def __init__(self, addr=("199.255.40.171", 28902), keyfile="keys.txt",
                 timeout=10):
        # basic definitions for later
        self.addr = addr
        self.last_error = None
        self.connected = False
        self.authenticated = False
        self.trust_server = True # use length values from server
        #   if trust_server is False, bytes are counted manually
        #   ALWAYS use trust_server until I fix my code
        # prepare an IPv4, TCP socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setblocking(0)
        self.s.settimeout(timeout)
        self.timeout = timeout
        # load the CD key if one is provided, else store key filename
        if type(keyfile) == str:
            if len(keyfile) == 23: self.cdkey = keyfile
            else: self.load_cd_key(keyfile)
        else:
            self.cdkey = None
            self.last_error = E_BAD_CDKEY

    def __enter__(self):
        """Utility routine for `with` support"""
        self.authenticate()
        return self #what

    def __exit__(self, et, ev, tb):
        """Utility routine for `with` support"""
        self.disconnect()

    def load_cd_key(self, filename):
        """Retrieves CD key from file"""
        # Because the master server requires a CD key IMMEDIATELY on connection,
        # we need to load it from a file (please do not hardcode any CD keys).
        try:
            with open(filename, 'r') as f:
                self.cdkey = f.readline().strip().upper()
        except IOError:
            self.cdkey = None
            self.last_error = E_READ_FAILURE
            return False
        if not re.match("\\-".join(["[0-9A-Z]{5}"]*4), self.cdkey):
            self.cdkey = None
            self.last_error = E_BAD_CDKEY
            return False
        return True

    def check_error(self):
        """Returns and resets last error value"""
        e = self.last_error
        self.last_error = None
        return e

    #   stuff for our socket
    def connect(self):
        """Connect to master server. Must authenticate upon connecting."""
        try:
            self.s.connect(self.addr)
        except socket.error:
            self.reset_socket()
        self.connected = True
        self.authenticated = False

    def disconnect(self):
        """Disconnect from master server"""
        try:
            self.s.close()
        except:
            pass # don't set error number as we could overwrite a real error
        self.connected = False
        self.authenticated = False

    def reset_socket(self):
        """Closes, recreates, and reopens socket"""
        self.disconnect()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setblocking(0)
        self.s.settimeout(self.timeout)
        try:
            self.s.connect(self.addr)
            self.connected = True
            self.authenticated = False
        except socket.error as e: handle_socket_error()
        except socket.timeout: self.last_error = E_TIMED_OUT

    def set_timeout(self, t):
        """Sets socket timeout to t seconds"""
        self.s.settimeout(t)
        self.timeout = t

    def read(self):
        """Reads data from socket, returns None if timeout"""
        try:
            self.last_error = None
            l = self.read_raw(4)
            l = struct.unpack("<I", l)[0]
#            print 'recv %d bytes' % l
            if l > 65535:
                # Sometimes, when using length-prefixed data, we lose
                # synchronization with the headers. I think I've fixed that by
                # creating read_raw, but it is always best to sanity-check our
                # inputs.
                sys.stderr.write("Receiving a ridiculous amount of data!")
                self.disconnect()
                self.last_error = E_LENGTH_OVERFLOW
            data = self.read_raw(l)
            if self.last_error: raise Exception()
            return data
        except Exception:
            return None

    def read_raw(self, l, timeout=None):
        """Read l bytes from socket"""
        if timeout == None: timeout = self.timeout
        out = ''
        ts = time()
        while len(out) < l and (time() - ts < timeout or timeout == 0):
            try:
                out += self.s.recv(1)
            except socket.timeout: self.last_error = E_TIMED_OUT
            except socket.error as e: self.handle_socket_error(e)
        return out

    def write(self, data):
        """Send data to server with length prefix"""
        try:
            self.s.send(lpdata(data))
        except socket.timeout: self.last_error = E_TIMED_OUT
        except socket.error as e: self.handle_socket.error(e)

    def handle_socket_error(self, e):
        """Sets last_error numbers for generic socket errors"""
        if "[Errno 9]" in e: self.last_error = E_SOCKET_CLOSED
        elif "[Errno 10057]" in e: self.last_error = E_SOCKET_NOT_OPEN
        else: self.last_error = E_SOCKET_FAILURE

#   authentication
    def make_hashes(self, challenge):
        """Prepare the two MD5 hashes for the authorization challenge"""
        # The first MD5 is that of the CD key
        # The second MD5 is CD key with challenge appended to it, no delimiter
        if not self.cdkey: load_cd_key()
        if not self.cdkey:
            self.last_error = E_BAD_CDKEY #CD key not found
        return (md5(self.cdkey).hexdigest(),
                md5(self.cdkey+challenge).hexdigest())

    def authenticate(self):
        """Authenticate CD key with the server, do this upon connecting."""
        #get the server's challenge request - happens upon connect
        if not self.connected: self.connect()
        c = unpack(self.read())
        h = self.make_hashes(c)
        #return challenge and info about client
        #if it isn't in the tuple i don't know what it does
        self.write("%s%s%s)\r\x00\x00\x05%s\x16\x04\x00\x00\x86\x80\x00\x00\
\x18\x00\x00\x00\x00" % tuple(map(pack, [h[0], h[1], "UT2K4CLIENT", "int"])))
        # check if we were approved
        a = unpack(self.read())
        if a != "APPROVED":
            self.disconnect()
            self.last_error = E_APPROVE_FAILURE
            return False
        self.write(pack("0014e800000000000000000000000000"))
        a = unpack(self.read())
        # now check if we were verified
        if a != "VERIFIED":
            self.disconnect()
            self.last_error = E_VERIFY_FAILURE
            return False
        self.authenticated = True
        return True

#   stuff for actually using the object
    def query_servers(self, qtype, qval, hdr=256):
        """Request of type qtype for servers matching qval"""
        # I have no idea what hdr means, maybe it's qtype type? Is it a byte?
        if not self.authenticated: self.authenticate()
        q = struct.pack("<H", hdr) + pack(qtype) + pack(qval) + '\x00'
        ts = time()
        self.write(q)
        l = struct.unpack("<IB", self.read())[0]
        ts = time() - ts
        sl = []
        sleep(ts) #give some time for data to arrive, why not
        if self.trust_server:
            for c in xrange(l):
                data = self.read()
                sl.append(MSServer(data))
        else:
            for c in xrange(max(0, l-4)): #why l-4? i have no idea
                #use raw socket when not trusting server
                print "Recv server %d of %d" % (c, l)
                lh = self.read_raw(4) #skip length header
                data = self.read_raw(8) #header ints/shorts
                nl = self.read_raw(1) #length of server name
                data += nl + self.read_raw(ord(nl)) #server name
                nl = self.read_raw(1) #length of map name
                data += nl + self.read_raw(ord(nl)) #map name
                data += self.read_raw(12) #remaining bytes/shorts/ints
                sl.append(MSServer(data))
                print sl[-1].name
        self.disconnect() # apparently server closes connection
        return sl


class MSServer(object):
    def __init__(self, data=''):
        """Storage class for server records received from master server"""
        self.rawline = data#.strip('\r\n') #During debugging, I read from a file
        self.ip = None
        self.port = None
        self.query_port = None
        self.cur_players = None
        self.max_players = None
        self.name = None
        self.map_name = None
        self.flags_byte = None
        self.filters_byte = None
        self.flags = {"Classic":False,
                      "Standard":False,
                      "Instagib":False,
                      "Listen":False,
                      "Latest":False,
                      "Stats":False,
                      "Password":False}
        self.filters = {"HasPlayers":None} # Not all filters are documented yet
        self.param_f = None # These are leftover data
        self.param_g = None # When you split up rawline as uint32 and lp-string,
        self.param_h = None # you got params a - h. that's how these got named
        if data:
            self.parse()

    def load(self, data):
        """Load raw line into this class"""
        self.rawline = data
        self.parse()

    def parse(self):
        """Translate self.rawline into class attribute variables"""
        i = 0
        ip, sp, qp = struct.unpack("<IHH", self.rawline[i:i+8])
        i += 8
        sn = clean_name(unpack(self.rawline, i))
        i += 1 + ord(self.rawline[i])
        mn = clean_name(unpack(self.rawline, i))
        i += 1 + ord(self.rawline[i])
        if len(self.rawline[i:i+12]) == 10: self.rawline += "\x00\x00" # >.>
        if len(self.rawline[i:i+12]) == 12:
            f, f1, cp, mp, fl, g, h = struct.unpack("<HBBBBHI",
                                                self.rawline[i:i+12])
        #define things now
            f += f1*65536
            self.param_f = f
            self.param_g = g
            self.param_h = h
            self.filters_byte = (h & 0xff0000) / 65536
            self.flags_byte = fl
            self.filters = {"HasPlayers":bool(self.filters_byte & 0x1)}
            self.flags = {"Classic":bool(fl & 0x40),
                          "Standard":bool(fl & 0x20),
                          "Instagib":bool(fl & 0x10),
                          "Listen":bool(fl & 0x8),
                          "Latest":bool(fl & 0x4),
                          "Stats":bool(fl & 0x2),
                          "Password":bool(fl & 1)}
            self.cur_players, self.max_players = (cp, mp)
        self.name, self.map_name = (sn, mn)
        self.port, self.query_port = (sp, qp)
        self.ip = int_to_ip(ip)
        return self #??

    def parse_debug(self):
        """I intended this to be troubleshooting code, but it does a good job \
at explaining how entries are formatted."""
        i = 0
        hm = ' '.join(map(lambda q:(hex(ord(q))+'   ')[2:4], self.rawline))
        i += 8
        print hm[0:3*i]
        print "|____IP____||_SP_||_QP_|\n"
        nl = ord(self.rawline[i])
        print hm[3*i:3*(nl+i+1)]
        print '   '+''.join(map(lambda q:q+'  ', self.rawline[i+1:i+nl]))
        print "|L||___Srv_Name --->\n"
        i += nl + 1
        ml = ord(self.rawline[i])
        print hm[3*i:3*(i+ml+1)]
        print '   '+''.join(map(lambda q:q+'  ', self.rawline[i+1:i+ml]))
        print "|L||___Map_Name --->\n"
        i += ml + 1
        print hm[3*i:3*(i+4)], "\n         CP\n|_Param_F_|\n"
        i += 4
        print hm[3*i:3*(i+4)], "\nMP FL __G__\n|_Param_G_|\n"
        i += 4
        print hm[3*i:3*(i+4)], "\n      FI   \n|_Param_H_|\n\n\n"
        i += 4

################################################################################
# Utility routines

def unpack(data, ofs=0):
    """Unpack a byte-length-prefixed string"""
    return data[ofs+1:ofs+ord(data[ofs])]

def pack(data):
    """Pack a byte-length-prefixed string"""
    data += '\x00'
    return chr(min(255, len(data)))+data

def lpdata(data):
    """Add 4-byte length prefix to data for sending to MS"""
    # This puts data into the same format that MSConnection.read() reads
    return struct.pack("<I", len(data))+data

def clean_name(s):
    """Remove formatting codes and encoding errors from UT2004 string"""
    # \x1b... removes color codes (master server may already misinterpret these)
    # \xa0 removes no-break spaces (WebAdmin seems to like nbsp a lot)
    # \xc2  appears to be some kind of encoding issue with nbsp
    # zzz  appears to be MS misinterpreting color codes
    return re.sub('\x1b...', '', s).replace('\xa0', ' ').replace('\xc2 ', ' ')\
           .replace('zzz ', '')

def int_to_ip(i):
    """Converts packed int into IP address string"""
    return "%d.%d.%d.%d" % struct.unpack("<BBBB", struct.pack("<I", i))

################################################################################
# Demonstration

def main():
    ms = MSConnection()
    sl = ms.query_servers("gametype", "xDeathMatch") # Search for DM servers
    print "Received %d servers!" % len(sl)
    c = 0
    for s in sorted(sl, key=lambda q:q.ip):
        # Sometimes (more often if not using trust_server), data isn't valid
        # I think read_raw fixed the length issues, so something is very wrong
        # if an invalid server is displayed with trust_server True
        if s.filters_byte == None: print "The following server is invalid!"
        print "%s:%d\t%s" % (s.ip, s.port, s.name)
        if s.filters_byte == None:
            c += 1
##            s.parse_debug()
    print "Invalid server records:", c


# Only run demo if running this module directly
if __name__ == "__main__": main()
