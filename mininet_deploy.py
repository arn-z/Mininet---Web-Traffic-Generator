#!/usr/bin/python
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.node import OVSSwitch
from mininet.topolib import TreeNet
import os, errno, subprocess
import time, datetime
#from multiprocessing import Process

def initialize_host(host, name, experiment):
	details = name + ' ' + experiment
	status = host.cmd('python3 /home/fastflux/files/trafficgen.py %s &' % details)
	print(status)

def initialize_dns(host, name, experiment):
	print("Starting resolver")
	status = host.cmd('python3 /home/fastflux/dnschef2/dnschef.py --fakeip 127.0.0.1 --fakeipv6 ::1 --exp {} -q &'.format(experiment))
	print(status)
	print("Dumping traffic")
	#folder = '/home/fastflux/experiments/{}/'.format(experiment)
	#host.cmdPrint('cd {}'.format(folder))
	#status = str(host.cmd('ifconfig'))
	#intf = status.splitlines()[0]
	#intf = intf.split('\t')[0]	
	#print(intf)
	#host.cmdPrint('sudo tcpdump -i h1-eth0 port 53 -w {}-{}-{}.pcap'.format(name, experiment, str(datetime.datetime.now())))
	#time.sleep(300)
	#print(status)

def scriptit(experiment, fanout_num):
	p = []
	hosts = []
	start = datetime.datetime.now()
	end = start + datetime.timedelta(days=1)
	x = 1


	# For the DNS resolver
	print("Initializing DNS resolver")
	host = network.get('h1')
	initialize_dns(host, str(host), experiment)


	# For the hosts
	print("Initializing hosts")
	for i in range(2,fanout_num + 1):
		host = network.get('h%d' %i)
		print("Starting experiment {} for {}".format(experiment, str(host)))
		initialize_host(host, str(host), experiment)

	print("Experiments initialized")
	while(datetime.datetime.now() < end):
		print("\n\n\n\n\n\n############################################################")
		print("## {}: {} end time {}".format(x, str(datetime.datetime.now()), str(end)))
		for i in range(2,fanout_num + 1):			
			host = network.get('h%d' %i)
			print(str(host))
			host.cmd('cat /etc/resolv.conf')
			#print(status)
		time.sleep(30)

		ps_out = subprocess.check_output(['ps', 'aux'])
		'''
		text = 'h1-{}'.format(experiment)
		if text in str(ps_out):
			print('DNS resolver is still running')
		else:
			print('DNS resolver is down. Restarting...')
			host = network.get('h1')
			initialize_dns(host, str(host), experiment)
		'''
		host = network.get('h1')
		host.cmd('ls')
		if 'dnschef' in str(ps_out):
			print('Resolver still running')
		else:
			print('Resolver is down... Restarting')
			initialize_dns(host, str(host), experiment)	


		for i in range(2, fanout_num + 1):
			text = 'h{} {}'.format(i, experiment)
			if text in str(ps_out):
				print('h{} still running'.format(i))
			else:
				print('h{} is down. Restarting...'.format(i))
				host = network.get('h%d' %i)
				print("Starting experiment {} for {}".format(experiment, str(host)))
				initialize_host(host, str(host), experiment)
		x += 1
		

	#### Error Handling (in case of dying processes)
	'''
	import sh
	print(sh.grep(sh.ps("cax"), 'something'))
	'''
	### Create a loading function which loads log file then continues from there



if __name__ == '__main__':
    
    experiment = raw_input("Input experiment title: ")
    fanout_num = int(raw_input("Indicate number of hosts: "))
	
	# Creating folder
    foldername = '/home/fastflux/experiments/{}/'.format(experiment)
    print(foldername)
    if not os.path.exists(os.path.dirname(foldername)):
        try:
            os.makedirs(os.path.dirname(foldername))
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise

	
    setLogLevel( 'info' )
	# Number of hosts = fanout^depth
	# Number of switches = fanout + 1
    network = TreeNet( depth=1, fanout=fanout_num, switch=OVSSwitch )
    network.addNAT().configDefault()
    network.start()

    # Wait for tcpdump before starting
    #print('Do tcpdump now....')
    # network.mn.terms += makeTerms([h1], term = term)
    #network.terms += makeTerm(h1)
    time.sleep(60)

    scriptit(experiment, fanout_num)
    CLI(network)
    network.stop()
