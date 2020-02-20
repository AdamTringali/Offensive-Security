from scapy.all import *
import cryptography
import getopt
from datetime import datetime
load_layer('http')
load_layer('tls')

def process_packet(packet):
    time = str(datetime.fromtimestamp(packet.time))
    ipLayer = packet.getlayer("IP")
    ethLayer = packet.getlayer("TCP")

    if packet.haslayer("HTTPRequest"):
        httpLayer = packet.getlayer("HTTP Request")
        print(time + " HTTP " + str(ipLayer.src) + ":" + str(ethLayer.sport) + " -> " + str(ipLayer.dst) + ":" + str(ethLayer.dport) + " " + str(httpLayer.Host.decode('UTF-8')) 
            + " " + str(httpLayer.Method.decode('UTF-8')) + " " + str(httpLayer.Path.decode('UTF-8')))

    if packet.haslayer("TLS"):
        tlsLayer = packet.getlayer("TLS")
        if packet.haslayer('TLSClientHello'):
            clientHello = packet.getlayer('TLSClientHello')
            
            version = "TLS x"

            if clientHello.version == 772:
                version = "TLS v1.3"
            elif clientHello.version == 771:
                version = "TLS v1.2"
            elif clientHello.version == 770:
                version = "TLS v1.1"
            elif clientHello.version == 769:
                version = "TLS v1.0"

            svrName = clientHello.getlayer("ServerName").servername.decode("UTF-8")

            print(time + " " + version + " " + str(ipLayer.src) + ":" + str(ethLayer.sport) + " -> " + str(ipLayer.dst) + ":" + str(ethLayer.dport) + " " + svrName)


argumentList = sys.argv[1:] 
options = "i:r:"

try: 
    # Parsing argument 
    arguments, values = getopt.getopt(argumentList, options) 
      
    # checking each argument 
    for currentArgument, currentValue in arguments: 
  
        if currentArgument in ("-r"): 
            packets = rdpcap(currentValue)
            for packet in packets:
                process_packet(packet)
            exit()
              
        elif currentArgument in ("-i"): 
            print ("-i specified")
            print(currentValue)
        else:
            print("else, " + currentArgument)
              
except (getopt.error, OSError) as err: 
    # output error, and return with an error code 
    print (str(err))
    exit()

# filter – BPF filter to apply.
# iface – interface or list of interfaces (default: None for sniffing on all interfaces).
# iface = "eth0"
# iface not allowed [eth1, wlan0]
sniff(prn=process_packet, count=0, iface="icmp")

