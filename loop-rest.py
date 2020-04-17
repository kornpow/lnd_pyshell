import base64, json, requests
import codecs
from pprint import pprint
from math import floor
from datetime import datetime, timedelta
import urllib.parse

base_url = 'http://127.0.0.1:8081'

def sendGetRequest(endpoint, data=""):
	global base_url
	target_url = base_url + endpoint.format(data)
	print("Sending Request to URL: {}".format(target_url))
	r = requests.get(target_url)
	pprint(r.text)
	return r.text

def sendPostRequest(endpoint,data=""):
	r = requests.post(base_url + endpoint, data=json.dumps(data))
	pprint(r.json())
	return r.json()


def listSwaps():
	url = '/v1/loop/swaps'
	loopreq = json.loads(sendGetRequest(url))
	print(loopreq)
	return loopreq

# Pass in result from list swaps
# This function will convert to url-safe
def getSwap(id_bytes):
	id_url_safe = id_bytes.replace('+','-').replace('/','_')
	id_percent_encoded = urllib.parse.quote(id_url_safe)
	url = f'/v1/loop/swap/{id_percent_encoded}'
	loopreq = json.loads(sendGetRequest(url))
	return loopreq

# id_safe = urllib.parse.quote_from_bytes(id_bytes.encode('UTF-8'),safe='')
# quote_from_bytes(bytes, safe=''
# # , safe=''

def sendGetUrl(endpoint):
	target_url = base_url + endpoint
	r = requests.get(target_url)
	pprint(r.text)
	return r.text

def sendPostUrl(endpoint,body):
	target_url = base_url + endpoint
	r = requests.post(target_url,data=json.dumps(body))
	pprint(r.text)
	return r.text

# LOOP TERMS
def loopOutTerms():
	url = '/v1/loop/out/terms'
	return sendGetUrl(url)

def loopInTerms():
	url = '/v1/loop/in/terms'
	return sendGetUrl(url)


# LOOP OUT COMMANDS
def loopOutQuote(amt):
	url = f'/v1/loop/out/quote/{amt}?conf_target=60'
	print(url)
	sendGetUrl(url)

	def loopOut():
	url = '/v1/loop/out'
	# 389800 + 280000
	max_swap_fee = 2000
	total_amt = 3356619
	# TUPLE: getNewAddress(),getNewAddress(),getNewAddress()
	addr_out = ()
	split_amt = int(total_amt / len(addr_out))
	chan_id = '1234editme'
	print(f"From Channel ID: {chan_id} Using {len(addr_out)} payments of {split_amt}.")
	for addr in addr_out:
		data1 = { 
				'max_swap_routing_fee': '200', 
				'sweep_conf_target': 15, 
				'max_miner_fee': '800', 
				'max_prepay_routing_fee': '200', 
				'max_swap_fee': f'{max_swap_fee}', 
				'max_prepay_amt': "2000", 
				'dest': f'{addr}', 
				'amt': f'{split_amt}', 
				'loop_out_channel': f'{chan_id}',
				'swap_publication_deadline': floor((datetime.now() + timedelta(minutes=5)).timestamp())
		}
		pprint(data1)
		sendPostUrl(url,data1)

# LOOP IN COMMANDS
def loopIn():
	url = '/v1/loop/in'
	loopin_data = { 
		'max_swap_fee': "1200", 
		'max_miner_fee': "1400", 
		'amt': "940000",
	}
	loopreq = sendPostRequest(url,loopin_data)
	return loopreq


def loopInQuote(amt):
	url = f'/v1/loop/in/quote/{amt}?conf_target=15'
	loopreq = sendGetRequest(url)
	print(loopreq)

url1 = '/v1/loop/in'
url2 = '/v1/loop/in/quote/{}'
url3 = '/v1/loop/out/quote/{}'
url4 = '/v1/loop/out'
url5 = 'v1/loop/swap/{}'
url6 = 'v1/loop/swaps'




loopreq = sendGetRequest(url2,250000)


loopin_data = { 
	'max_swap_fee': "6000", 
	'max_miner_fee': "2000", 
	'amt': "400000",
	'external_htlc': True, 
}

loopout_data = {

}
loopreq = sendPostRequest(url1,data)
