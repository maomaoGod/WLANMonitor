import subprocess as sub
import re
import json
import signal
import sys
import getopt
import time

# TODO: Smarter handling of changing IPs, unrecognized traffic, new devices addition.
# TODO: Install as a daemon
# TODO: Send mail with alerts

def sigint_handler(signal, frame):
	time.sleep(1)
	print ""
	print "Learned IPs for network:"
	for mac in learned_ips.keys():
		print known_macs[mac],':',','.join(learned_ips[mac])

	print ""
	print "Unrecognized traffic:"
	print ','.join(unrecognized)

	sys.exit(0)

signal.signal(signal.SIGINT, sigint_handler)

def get_line_traffic(src_mac, dst_mac, src_host, dst_host):
	return "Src. MAC: {0:<18} Dst. MAC: {1:<18} Src. HOST: {2:<20} Dst. Host: {3:<20}".format(src_mac,dst_mac,src_host, dst_host)

with open('known_macs.json') as known_macs_file:
	config = json.load(known_macs_file)
	known_macs = config['known_macs']
	known_macs['ff:ff:ff:ff:ff:ff'] = 'Broadcast'
	known_macs['01:00:5e:00:00:fb'] = 'Multicast DNS - IPv4'
	known_macs['01:00:5e:00:00:16'] = 'Multicast DNS - igmp.mcast.net'
	known_macs['01:00:5e:00:00:fc'] = 'Multicast DNS - name not found'
	known_macs['01:00:5e:7f:ff:fa'] = 'Multicast DNS - name not found 2'
	known_macs['33:33:00:'] = 'IPv6 Multicast'

def find_in_known_macs(mac):
	return len(filter(lambda m: mac.startswith(m),known_macs)) > 0

learned_ips = {}
unrecognized = []

def learn_ip(mac, host):
	if host.startswith(config['subnet']):
		if mac in known_macs.keys():
			if mac not in learned_ips.keys():
				learned_ips[mac] = []
		
			if host not in learned_ips[mac]:
				learned_ips[mac].append(host)

def normalize_port(st):
	if st.count(".") > 3:
		port_loc = st.rfind(".")
		return st[:port_loc]

	return st

def normalize_last(st):
	if st[-1] == ',' or st[-1] == ':':
		return st[:-1]

	return st

is_debug = False
is_verbose_debug = False

def get_args(argv):
	global is_debug
	global is_verbose_debug

	try:
		opts, args = getopt.getopt(argv, "dv", ["debug", "verbose"])
	except getopt.GetoptError:
		print "Usage: python analyzeWlan.py [-d] [-v]"
		sys.exit(2)

	for opt, arg in opts:
		if opt in ("-d", "--debug"):
			is_debug = True

		if opt in ("-v", "--verbose"):
			is_verbose_debug = True

	
def run():
	p = sub.Popen(('tcpdump', '-i', 'wlan1', '-e', '-n', '-l'), stdout=sub.PIPE)
	for row in iter(p.stdout.readline, b''):
		line = row.rstrip()
		if is_verbose_debug:
			print line

		data = re.match(r'[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]* ([A-F0-9:]+) > ([A-F0-9:]+), .* ([^\s]+) (>|tell) ([^\s]+)', line, re.I|re.S)
		if data:
			src_mac = data.group(1)
			dst_mac = data.group(2)
			src_host = data.group(3)
			dst_host = data.group(5)
			is_arp = data.group(4) == 'tell'
	
			# In ARP query packets, "who is X tell Y" means that Y is the source, X is the destination IP, and query is to broadcast MAC. So need to flip src and dst hosts
			if is_arp:
				tmp = src_host
				src_host = dst_host
				dst_host = tmp

			# Normalize hosts to not include the port, if has one
			src_host = normalize_last(src_host)
			dst_host = normalize_last(dst_host)

			src_host = normalize_port(src_host)
			dst_host = normalize_port(dst_host)
			
			if is_debug:
				print "MATCH!",get_line_traffic(src_mac,dst_mac,src_host,dst_host)

			if not find_in_known_macs(src_mac):
				print "Unrecognized src. traffic!",src_mac
				unrecognized.append(src_mac)	
	
			if not find_in_known_macs(dst_mac):
				print "Unrecognized dst. traffic!",dst_mac		
				unrecognized.append(dst_mac)

			learn_ip(src_mac, src_host)
			learn_ip(dst_mac, dst_host)
		else:
			if is_debug:
				print "No match:",line


if __name__ == "__main__":
	get_args(sys.argv[1:])
	run()
