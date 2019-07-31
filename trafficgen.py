#!/usr/bin/python

#
# written by @eric_capuano
# https://github.com/ecapuano/web-traffic-generator
#
# published under MIT license :) do what you want.
#
#20170714 shyft ADDED python 2.7 and 3.x compatibility and generic config



#########
#######
####		websiteoutlook.com
##
#
from __future__ import print_function
import requests, re, time, random, os, datetime, sys, subprocess
from scipy.stats import lognorm
import numpy as np
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from time import sleep
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions
from selenium.common.exceptions import NoSuchElementException


try:
	import config
except ImportError:
	clickDepth = 5 # how deep to browse from the rootURL
	minWait = 5 # minimum amount of time allowed between HTTP requests
	maxWait = 15 # maximum amount of time to wait between HTTP requests
	debug = True # set to True to enable useful console output

	# use this single item list to test how a site responds to this crawler
	# be sure to comment out the list below it.
	#rootURLs = ["https://digg.com/"] 

	rootURLs = [
		"https://digg.com/",
		"https://www.yahoo.com",
		"https://www.reddit.com",
		"http://www.cnn.com",
		"http://www.ebay.com",
		"https://en.wikipedia.org/wiki/Main_Page",
		"https://austin.craigslist.org/"
		]


	# items can be a URL "https://t.co" or simple string to check for "amazon"
	blacklist = [
		"https://t.co", 
		"t.umblr.com", 
		"messenger.com", 
		"itunes.apple.com", 
		"l.facebook.com", 
		"bit.ly", 
		"mediawiki", 
		".css", 
		".ico", 
		".xml", 
		"intent/tweet", 
		"twitter.com/share", 
		"signup", 
		"login", 
		"dialog/feed?", 
		".png", 
		".jpg", 
		".json", 
		".svg", 
		".gif", 
		"zendesk",
		"clickserve",
		"static"
		]  

	# must use a valid user agent or sites will hate you
	userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) ' \
		'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36'


################################################################### Browsing Modules ##################################################################
def time_effects():
	if (datetime.datetime.now().hour in range(9,11)) or (datetime.datetime.now().hour in range(14,17)): # peak times, browsing is continuous
		browsing_probability = 1
		i = stretch - 1
	elif (datetime.datetime.now().hour in range(7, 9)) or (datetime.datetime.now().hour in range(13, 14)): # rising time, browsing increases
		i = 0
	elif (datetime.datetime.now().hour in range(11, 13)) or (datetime.datetime.now().hour in range(17, 20)): # falling time, browsing decreases
		i = stretch - 1
	else: # off times, browsing is dependent on 
		i = 0
	return int(i)

def doRequest(url, depthmax):
	global dataMeter
	global goodRequests
	global badRequests
	global i
	global values
	global stretch
	global browsing_probability
	global end
	final_sleep = 0
	sleepTime = random.randrange(config.minWait,config.maxWait)

	
	# Day time effects to browsing
	if (datetime.datetime.now().hour in range(9,11)) or (datetime.datetime.now().hour in range(14,17)): # peak times, browsing is continuous
		i = i + random.randrange(2, random.randrange(4,7))
		if (i < stretch - 1):
			browsing_probability = values[i]
		else:	
			browsing_probability = 1
			i = stretch - 1
		print("Peak Time: browsing is continuous: browsing_probability =", browsing_probability)
		setting = 'Peak'
	elif (datetime.datetime.now().hour in range(7, 9)) or (datetime.datetime.now().hour in range(13, 14)): # rising time, browsing increases
		i = i + random.randrange(1, random.randrange(2,7))
		if (i < stretch - 1):
			browsing_probability = values[i]
		else:
			browsing_probability = 1
			i = stretch - 1
		print("Rising Time: browsing increases: browsing_probability =", browsing_probability)
		setting = 'Rising'

	elif (datetime.datetime.now().hour in range(11, 13)) or (datetime.datetime.now().hour in range(17, 20)): # falling time, browsing decreases
		i = i - random.randrange(0, random.randrange(3,10))
		if (i > 0):
			browsing_probability = values[i]
		else:
			browsing_probability = 0
			i = 0
		print("Fall Time: browsing decreases: browsing_probability =", browsing_probability)
		setting = 'Falling'
	else: # off times, browsing is dependent on
		i = i - random.randrange(2, 7)
		if (i > 0):
			browsing_probability = values[i]
		else:
			browsing_probability = 0
			i = 0
		'''
		browsing_probability = 1
		i = stretch - 1
		'''
		print("Off Time: browsing is sparse: browsing_probability =", browsing_probability)
		setting = 'Off'
	print("Counter: ", i)

	if (browsing_probability > 0.4):
		if config.debug:
			print("requesting: %s" % url)
	
		headers = {'user-agent': config.userAgent}
	
		try:
			r = requests.get(url, headers=headers, timeout=5)
			
		except:
			time.sleep(30) # else we'll enter 100% CPU loop in a net down situation
			return False
		
		status = r.status_code
	
		pageSize = len(r.content)
		dataMeter = dataMeter + pageSize

	
		if config.debug:
			print("Page size: %s" % pageSize)
			if ( dataMeter > 1000000 ):
				print("Data meter: %s MB" % (dataMeter / 1000000))
			else:
				print("Data meter: %s bytes" % dataMeter)
	
		if ( status != 200 ):
			badRequests+=1
			if config.debug:
				print("Response status: %s" % r.status_code)
			if ( status == 429 ):
				if config.debug:
					print("We're making requests too frequently... sleeping longer...")
				sleepTime+=30
		else:
			goodRequests+=1
	
		# need to sleep for random number of seconds!
		if config.debug:
			print("Good requests: %s" % goodRequests)
			print("Bad reqeusts: %s" % badRequests)
			final_sleep = int((sleepTime * random.uniform(1,3)/depthmax))
			
			try:
				driver = webdriver.PhantomJS()
				driver.get(url)
			except:
				time.sleep(5)
			#driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
			
			print("Sleeping for %d seconds..." % final_sleep)
		time.sleep(final_sleep)
		driver.quit()

	else:
		if (datetime.datetime.now().hour not in range(7,20)):
			if (browsing_probability == 0):
				while(datetime.datetime.now().hour not in range(7, 20)):
					print("Sleeping for %d while waiting for Rise time" % config.maxWait)
					time.sleep(config.maxWait)
			else:
				print("Sleeping for %d" % config.minWait)
				time.sleep(config.minWait)
		else:
			print("Sleeping for ", config.minWait)
			time.sleep(1)
	try:
		return setting, r
	except:
		return setting, 0

def getLinks(page):
	links=[]

	pattern=r"(?:href\=\")(https?:\/\/[^\"]+)(?:\")"
	
	matches = re.findall(pattern,str(page.content))
	
	for match in matches: # check all matches against config.blacklist
		if any(bl in match for bl in config.blacklist):
			pass
		else:
			links.insert(0,match)
		
	return links

def browse(urls, filename):
	global browsing_probability
	global currURL
	global end
	global i
	x = []
	depthmax = random.randrange(7, config.clickDepth)

	
	for ctr in range(0, len(urls)-random.randrange(0,len(urls)-20)):
		urlCount = len(urls)
		index = random.randrange(0, urlCount)
		while index in x:
			index = random.randrange(0, urlCount)
		x.append(index)
		url = urls[index]
		print(url)
		try:
			setting, page = doRequest(url, depthmax)  # hit current root URL
		except:
			continue
		if page:
			links = getLinks(page) # extract links from page
			linkCount = len(links)
		else:
			if config.debug:
				print("Error requesting %s" % url)
			continue


		depth=0
		while ( depth < depthmax ):
			if (browsing_probability == 0):
				break
			else:
				if config.debug:
					print("------------------------------------------------------")
					print("config.blacklist: %s" % config.blacklist )
				# set the link count, which will change throughout the loop
				linkCount = len(links)
				if ( linkCount > 1): # make sure we have more than 1 link to use

					if config.debug:
						print("URL: %s / %s -- Depth: %s / %s" \
							% (currURL,urlCount,depth,depthmax))
						print("Choosing random link from total: %s" % linkCount)
		
					randomLink = random.randrange(0,linkCount - 1)
	
					if config.debug:
						print("Link chosen: %s of %s" % (randomLink,linkCount))
		
					clickLink = links[randomLink]	
	
					try:
						# browse to random link on rootURL
						setting, sub_page = doRequest(clickLink, depthmax)
						if sub_page:
							checkLinkCount = len(getLinks(sub_page))
							day = str(datetime.datetime.now()).split(' ')[0]
							tim = str(datetime.datetime.now()).split(' ')[1]
							another_line = '{},{},{},{},{},{},{}'.format(day, tim, setting, 'OK', browsing_probability, i, clickLink)
							new = another_line + '\n'
							f = open(filename, 'a')
							f.write(new)
							f.close()

						else:
							if config.debug:
								print("Error requesting %s" % url)
								day = str(datetime.datetime.now()).split(' ')[0]
								tim = str(datetime.datetime.now()).split(' ')[1]
								another_line = '{},{},{},{},{},{},{}'.format(day, tim, setting, 'ERROR', browsing_probability, i, clickLink)
								new = another_line + '\n'
								f = open(filename, 'a')
								f.write(new)
								f.close()
							break
		
		
						checkLinkCount = len(getLinks(sub_page))

						# make sure we have more than 1 link to pick from 
						if ( checkLinkCount > 1 ):
							# extract links from the new page
							links = getLinks(sub_page)
						else:
							# else retry with current link list
							if config.debug:
								print("Not enough links found! Found: %s  -- " \
									"Going back up a level" % checkLinkCount)
							config.blacklist.insert(0,clickLink)
							# remove the dead-end link from our list
							del links[randomLink]
					except:
						if config.debug:
							print("Exception on URL: %s  -- " \
								"removing from list and trying again!" % clickLink)
						# I need to expand more on exception type for config.debugging
						config.blacklist.insert(0,clickLink)
						# remove the dead-end link from our list
						del links[randomLink] 
						pass
					# increment counter whether request was successful or not 
					# so that we don't end up in an infinite failed request loop
					depth+=1
						
				else:
					# we land here if we went down a path that dead-ends
					# could implement logic to simply restart at same root
					if config.debug:
						print("Hit a dead end...Moving to next Root URL")
					config.blacklist.insert(0,url)
					depth = config.clickDepth 
			
		'''
		if (browsing_probability == 0):
			print("Off time and browsing_probability = 0.")
			while(int(datetime.datetime.now().hour) not in  range(7,9)):
				print("Sleeping for %d while waiting for Rise time" % config.maxWait)
				time.sleep(config.maxWait)
		else:	
		'''	
		currURL+=1 # increase rootURL iteration
		if (datetime.datetime.now() > end):
			break
		
		if config.debug:
			print("Done.")

########################################################################## Start Browsing ##########################################################################

# initialize our global variables
dataMeter = 0
goodRequests = 0
badRequests = 0
browsing_probability = 0
arguments = sys.argv
folder = '/home/fastflux/experiments/{}/'.format(arguments[2])

ps_out = subprocess.check_output(['ls', folder])
tag = '{}-{}'.format(arguments[1], arguments[2])

# Log exists
if tag in str(ps_out):
	print('Log file exists')
	files = []
	# Getting files in directory
	print('Get files in directory')
	for item in ps_out.splitlines():
		files.append(str(item).strip('b').replace("'", ""))
	print('Getting filename')
	# Getting filename
	for item in files:
		if tag in item:
			filename = item
			break
	print('Opening %s' % filename)		
	# Opening file
	filename = '{}{}'.format(folder, filename)
	f = open(filename, 'r')
	dump = f.read()
	f.close()
	'''
	for i in range(0,6):
		print(dump.splitlines()[i])
	'''
	mean = float(dump.splitlines()[2].strip('Mean: '))
	stddev = float(dump.splitlines()[3].strip('Stddev: '))
	ranger = float(dump.splitlines()[4].strip('Time Space: 0 to '))
	start = str(dump.splitlines()[5].strip('Start: '))
	start = start.replace('-', ' ').replace(':', ' ').replace('.', ' ')
	start = start.split(' ')
	start = datetime.datetime(int(start[0]), int(start[1]), int(start[2]), int(start[3]), int(start[4]), int(start[5]), int(start[6]))
	stretch = float(dump.splitlines()[6].strip('Stretch: '))
	try:
		last_log = dump.splitlines()[len(dump.splitlines())-1].split(',')
		last_log = last_log[0] + ' ' + last_log[1]
		last_log = last_log.replace('-', ' ').replace(':', ' ').replace('.', ' ')
		last_log = last_log.split(' ')
		last_log = datetime.datetime(int(last_log[0]), int(last_log[1]), int(last_log[2]), int(last_log[3]), int(last_log[4]), int(last_log[5]), int(last_log[6]))
		timer = last_log + datetime.timedelta(minutes = 30)
		print('Last log: ', str(last_log), '| timer: ', timer)
		if (datetime.datetime.now() < timer):
			i = int(dump.splitlines()[len(dump.splitlines())-1].split(',')[5])
		else:
			print('Last browsing activity exceeded timer. Initializing counter using day time')	
			i = time_effects()
	except:
		print('No browsing activity logged')
		i = time_effects()

# No log exists
else:
	print('No log file exists')
	mean = random.uniform(0.3,0.8)
	stddev = random.uniform(0.5, 0.95)
	ranger = random.randrange(2,8)
	#ranger = 3
	stretch = random.randrange(100,400)
	start = datetime.datetime.now()
	timestamp = arguments[1] + '-' + arguments[2] + '-' + str(start) + '.txt'
	filename = '{}{}'.format(folder, timestamp)

	details = 'Host: {}\nExperiment: {}\nMean: {}\nStddev: {}\nTime Space: 0 to {}\nStart: {}\nStretch: {}\n\n\nDay,Time,Setting,Status,Browsing Probability,Link\n'.format(arguments[1], arguments[2], mean, stddev, ranger, start, stretch)

	f = open(filename, 'a')
	f.write(details)
	f.close()
	i = time_effects()

end = start + datetime.timedelta(days=1)
print("################### Log Distribution Characteristics of %s ###################" % arguments[1])
print("\tExperiment:", arguments[2])
print("\tMean:", mean)
print("\tStddev:", stddev)
print("\tTime Space: 0 to", ranger)
print("\tStart: {}".format(start))
print("\tStretch: {}".format(stretch))
print("##############################################################################")


time_space = np.linspace(0,ranger,stretch)
dist = lognorm([stddev], loc = mean)
values = dist.cdf(time_space)
currURL = 1


print(i)
print(browsing_probability)

while (datetime.datetime.now() < end):
	print("Traffic generator started...")
	print("----------------------------")
	print("https://github.com/ecapuano/web-traffic-generator")
	print("")
	print("Clicking %s links deep into %s different root URLs, " \
		% (config.clickDepth,len(config.rootURLs)))
	print("waiting between %s and %s seconds between requests. " \
		% (config.minWait,config.maxWait))
	print("")
	print("This script will run indefinitely. Ctrl+C to stop.")
	browse(config.rootURLs, filename)
	
print('Browsing exceeded {}'.format(end))
print('Terminating traffic generator...')
