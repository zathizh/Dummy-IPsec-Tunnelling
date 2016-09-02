import socket, os, struct, sys
from ctypes import *
from struct import *
from fcntl import ioctl
from itertools import cycle
from Crypto.Cipher import AES

ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20

ESP_HEADER_LEN = 8
ESP_TRAILER_LEN = 4
ESP_AUTH_LEN = 4

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
TUNMODE = IFF_TUN

# IP header
class IP(Structure):
    _fields_ = [
        ("version", c_ubyte, 4),
        ("ihl", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
        ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        # map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        self.src_address = socket.inet_ntoa(struct.pack("@I",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I",self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

class ESPH(Structure):
    _fields_ = [
        ("spi", c_uint32),
        ("snum", c_uint32)
        ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass


class ESPT(Structure):
    _fields_ = [
        ("plen", c_ubyte),
        ("nheader", c_ubyte),
        ("icv", c_uint32)
        ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

class ICMP(Structure):
    __fields_ = [
	("type", c_ubyte),
	("code", c_ubyte),
	("chksum", c_ushort),
	("omsi", c_uint32)
	]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

def checksum(msg):
    s = 0
    for i in range(0, len(msg)-3, 4):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)  + (ord(msg[i+2]) << 16) + (ord(msg[i+3]) << 24)
        s = s + w

    s = (s>>32) + (s & 0xffffffff);
    s = s + (s >> 32);
    s = ~s & 0xffffffff
    
    return s

def tun_open(devname):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', 'asa0', IFF_TUN | IFF_NO_PI)
    ifs = ioctl(fd, TUNSETIFF, ifr)
    return fd

source_ip = '192.168.12.132'
dest_ip = '192.168.12.133'

# ip header fields
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0  # kernel will fill the correct total length
ip_id = 54321   #Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = 50
ip_check = 0    # kernel will fill the correct checksum
ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
ip_daddr = socket.inet_aton ( dest_ip )

ip_ihl_ver = (ip_ver << 4) + ip_ihl

# the ! in the pack format string means network order
ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

# esp header fields
esp_spi = 0
esp_snum = 0
esp_plength = 0
esp_nheader = 0

recvsock= socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
sendsock= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
recvsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sendsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
recvsock.bind(('eth0', 0))
sendsock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

fd = tun_open("asa0")
e = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')

while True:
    buf = ''
    while True:
    	data = recvsock.recvfrom(65565)[0]
    	app_data = data[ETH_HEADER_LEN + IP_HEADER_LEN + ESP_HEADER_LEN:-(ESP_AUTH_LEN)]
	pad = len(app_data)%16
	if pad == 0 and len(app_data) >= 20:
	    buf  = e.decrypt(app_data)
    	    if IP(buf).protocol_num == 1:
		print(str(IP(data[ETH_HEADER_LEN:]).src_address)+ " -> " + str(IP(data[ETH_HEADER_LEN:]).dst_address))
	    	break

    os.write(fd, buf[:-(ESP_TRAILER_LEN + pad)]) 
    print('Wrote ' + str(len(buf[:-ESP_TRAILER_LEN]))+ ' bytes to asa0')

    raw_buffer = os.read(fd, 1600)

    esp_plength = (len (raw_buffer) + ESP_TRAILER_LEN) %16

    esp_snum += 1
    esp_header = pack('!LL', esp_spi, esp_snum)
    esp_trailer = pack('!HH', esp_plength, esp_nheader)

    if (esp_plength != 0):
	raw_buffer = raw_buffer + "0"*esp_plength + esp_trailer

    app_data = e.encrypt(raw_buffer)
    esp_icv = checksum(app_data+esp_trailer)
    esp_auth = pack("!L", esp_icv)

    packet = ip_header + esp_header + app_data + esp_auth

    sendsock.sendto(packet, (dest_ip , 0 ))
