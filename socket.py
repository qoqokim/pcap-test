import socket
import struct

conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

def get_mac(data):
	sres = ""
	dres = ""
	dst, src = struct.unpack('! 6s 6s', data[:12])
	for i in range (6):
		sres += "%02X" % src[i]
		if i !=5 :
			sres += ":"
		dres += "%02X" % dst[i]
		if i !=5 :
			dres += ":"
	print("Src Mac :",sres)
	print("Dst Mac :",dres)

	
def get_ip(data):
	src, dst = struct.unpack('! 4s 4s ', data[26:34])
	print("Src IP : ",str(int(src[0]))+"."+str(int(src[1]))+"."+str(int(src[2]))+"."+str(int(src[3])))
	print("Dst IP : ",str(int(dst[0]))+"."+str(int(dst[1]))+"."+str(int(dst[2]))+"."+str(int(dst[3])))

def get_port(data):
	src, dst = struct.unpack('! H H', data[34:38])
	print("Src Port :",int(src), "\nDst Port :",int(dst))

while True:
	data, addr = conn.recvfrom(65536)
	dst, src, eth_type = struct.unpack('! 6s 6s H', data[:14])
	ip_proto = data[23]

	if eth_type == 0x800:
		if ip_proto == 6:
			print("\n******************* packet ***********************")
			get_mac(data)	
			get_ip(data)
			get_port(data)
