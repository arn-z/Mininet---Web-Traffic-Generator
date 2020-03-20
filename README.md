# Mininet---Web-Traffic-Generator

## *mininet_deploy.py*
To run it, first edit your nameserver to point to the first host (10.0.0.1).  
Asks for the number of hosts and experiment title. It automatically creates the experiment directory and the log files for the hosts.  
The first host is automatically selected as the one running *dnschef.py* whch acts as a DNS resolver for the other hosts.  
The rest of the hosts will generate traffic by running *trafficgen.py*   
If the run encounters an error, you can continue running it by using the same experiment name.  
Each experiment is good for one day and it will automatically stop.  


## *trafficgen.py*

It is a modified version of (@eric_capuano https://github.com/ecapuano/web-traffic-generator).
A configuration file is generated randomly for each host which defines their browsing capability.
A daytime behavior feature is also included to mimic the browsing behavior of a typical small office setup.

* **Off time** (12 MN - 7 AM, 8PM - 12 MN) - browsing probability is low/close to zero.
* **Rising time** (7 AM - 9 AM, 1 PM - 2 PM) - browsing probability increases.
* **Peak time** (9 AM - 11 AM, 2 PM - 5 PM) - browsing probabiity is at maximum/constant.
* **Falling time** (11 AM - 1 PM, 5 PM - 10 PM) - browsing probability decreases.
A log is also generated for each host which indicates the sites that they were able to visit. This also includes their configuration file.
Insted of using GET requests(which is light), phantomjs was used to mimic the traffic being generated when browsing.

## *dnschef.py*
It is modified version of the original dnschef (http://thesprawl.org/projects/dnschef/).
A select number of hosts are randomly chosen to be spoofed.
There are three modes:
1) **Pure proxy** - requests are just forwarded to public DNS servers
2) **Proxy & Pure Spoofing** - all the requests from the selected hosts are automatically spoofed. The rest are proxied.
3) **Proxy & Periodical Spoofing** - the selected hosts take turns on being spoofed. Each turn is good for ten minutes.
