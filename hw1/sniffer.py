from scapy.all import *
import cryptography
import getopt
from datetime import datetime
load_layer('http')
load_layer('tls')

def process_packet(packet):
    # print(packet.show2())
    time = str(datetime.fromtimestamp(packet.time))
    ipLayer = packet.getlayer("IP")
    ethLayer = packet.getlayer("TCP")

    if packet.haslayer("HTTPRequest"):
        # print(packet.show())
        httpLayer = packet.getlayer("HTTP Request")
        print(time + " HTTP " + str(ipLayer.src) + ":" + str(ethLayer.sport) + " -> " + str(ipLayer.dst) + ":" + str(ethLayer.dport) + " " + str(httpLayer.Host.decode('UTF-8')) 
            + " " + str(httpLayer.Method.decode('UTF-8')) + " " + str(httpLayer.Path.decode('UTF-8')))

    if packet.haslayer("TLS"):
        tlsLayer = packet.getlayer("TLS")
        packet.show2()
        # print(tlsLayer.type)
        if tlsLayer.type == 22:
            print("aa")

            #####33print(tlsLayer.msg)
            exit()

        #print(packet.show2())
        #exit()
    	#print("packet has tcp")


argumentList = sys.argv[1:] 
options = "i:r:"

try: 
    # Parsing argument 
    arguments, values = getopt.getopt(argumentList, options) 
      
    # checking each argument 
    for currentArgument, currentValue in arguments: 
  
        if currentArgument in ("-r"): 
            print ("-r specified")
            print(currentValue)
            packets = rdpcap(currentValue)
            for packet in packets:
                process_packet(packet)


           
                
              
        elif currentArgument in ("-i"): 
            print ("-i specified") 
              
except getopt.error as err: 
    # output error, and return with an error code 
    print (str(err))


sniff(prn=process_packet, count=100)






# sniff(count=10,prn=process_packet)

# load_layer("http")

# load_layer("tls")
