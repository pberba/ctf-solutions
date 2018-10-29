from scapy.all import *

pcap = rdpcap('final_fuzz.pcap')

with open('out.png', 'wb') as f:
	for e in pcap:
		if IP not in e:
			continue
		if e[IP].src != '192.168.42.129':
			continue
		if DNS not in e:
			continue
		dns = e[DNS]
		if Padding not in e:
			continue
		f.write(str(dns[Padding]).lstrip(chr(0)))
