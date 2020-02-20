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
rflag = 0
iflag = 0
interface = ""
expression = ""
filename = ""

try: 
    # Parsing argument 
    arguments, values = getopt.getopt(argumentList, options) 

    if len(argumentList)%2 == 1:
        expression = argumentList[-1]
      
    # checking each argument 
    for currentArgument, currentValue in arguments: 
  
        if currentArgument in ("-r"): 
            rflag = 1
            filename = currentValue
              
        if currentArgument in ("-i"): 
            iflag = 1
            interface = currentValue
              
except (getopt.error, OSError) as err: 
    # output error, and return with an error code 
    print (str(err))
    exit()

# filter – BPF filter to apply.
# iface – interface or list of interfaces (default: None for sniffing on all interfaces).
# iface = "eth0"
# iface not allowed [eth1, wlan0, icmp]
if rflag == 1:
    if iflag == 1:
        print("-r specified. '-i " + interface + "' discarded.")
    try:
        packets = rdpcap(filename)
        for packet in packets:
            if not expression == ""
                if expression in packet:
                    process_packet(packet)
            else:
                process_packet(packet)
    except (OSError, FileNotFoundError) as err:  
        print (str(err))

    exit()


if rflag == 0 and iflag == 0 and expression == "":
    print("no r or i flag. sniffing indefinitely")
    sniff(prn=process_packet, count=0)
elif iflag == 1:
    if expression == "":
        try: 
            sniff(prn=process_packet, count=0, iface=interface)
        except:
            print("error")
            exit()
    else:
        try: 
            sniff(prn=process_packet, count=0, iface=interface, filter=expression)
        except:
            print("error")
            exit()
elif expression != "":
    print("BPF filter: " + expression)
    try: 
        sniff(prn=process_packet, count=0, filter=expression)
    except:
        print("BPF filter errors:", sys.exc_info()[0])
        exit()


