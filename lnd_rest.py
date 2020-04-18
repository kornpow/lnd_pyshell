import requests
import base64, codecs, json, requests
import binascii
import code
from pprint import pprint, pformat
import pandas
from pandas import Series
from math import floor, fsum
from datetime import datetime, timedelta
from hashlib import sha256
pandas.set_option('display.max_colwidth', None)
pandas.set_option('display.max_rows', None)
import traceback
import os
import urllib.parse

# LND_DIR = '/home/lightning/.lnd/'
# LND_DIR = f'{os.getenv("HOME")}/kornpow_cloud/.lnd/'
LND_DIR = f'{os.getenv("HOME")}/.lnd/'
print(LND_DIR)
# Get Macaroon into a useable form!
# TODO: delete me?
# with open(LND_DIR + 'mainnet/admin.macaroon', 'rb') as f:
# 	hex_content = binascii.b2a_hex(f.read())

# OR
# This one is better!
macaroon = codecs.encode(open(LND_DIR + 'data/chain/bitcoin/mainnet/admin.macaroon', 'rb').read(), 'hex')
# macaroon = codecs.encode(open(LND_DIR + 'test.macaroon', 'rb').read(), 'hex')
headers = {'Grpc-Metadata-macaroon': macaroon}

cert_path = LND_DIR + 'tls.cert'

# {'Grpc-Metadata-macaroon': b''}
# node_ip = ''
base_url = f'https://{os.getenv("NODE_IP")}:8080'
print(base_url)

# THIS HOLDS A CACHE OF PUB-KEY to ALIAS CONVERSIONS
pkdb = {}

# ERROR List
# {'error': 'permission denied', 'message': 'permission denied', 'code': 2}

##### Base GET/POST  REQUEST
def sendPostRequest(endpoint,data="",debug=False):
	url = base_url + endpoint
	r = requests.post(url, headers=headers, verify=cert_path, data=json.dumps(data))
	# pprint(r.json())
	return r.json()

def sendGetRequest(endpoint, ext="", body=None, debug=False):
	url = base_url + endpoint.format(ext)
	if debug:
		print(f"GET: {url}")
	r = requests.get(url, headers=headers, verify=cert_path, data=body)
	return r.json()

def sendDeleteRequest(endpoint, data="",debug=False):
	url = base_url + endpoint
	if debug:
		print(f"DELETE: {url}")
	r = requests.delete(url, headers=headers, verify=cert_path, data=json.dumps(data))
	# pprint(r.json())
	return r.json()


##### WALLET UNLOCK! 
def unlockWallet():
	password = base64.b64encode(os.getenv('PASS').encode('UTF-8')).decode()
	sendPostRequest('/v1/unlockwallet',
		{
			'wallet_password': password,
			# 'recovery_window': 0,
			# channel_backups: None
		})


##### Payment Functions
def sendPaymentByReq(payreq, oid=None, lasthop=None, allow_self=False):
	# TODO: Add ability for this to return true/false success of payment
	url = '/v1/channels/transactions'
	data = {}
	data['payment_request'] = payreq
	if oid:
		data['outgoing_chan_id'] = oid
	if lasthop:
		data['last_hop_pubkey'] = base64.b64encode(bytes.fromhex(lasthop)).decode()
	if allow_self:
		data['allow_self_payment'] = True
	# if outid != None:
	# 	data = {'payment_request': payreq, 'outgoing_chan_id': outid}
	# data = {'payment_request': payreq, 'payment_hash_string':'2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'}
	lnreq = sendPostRequest(url, data)
	pprint(lnreq)
	try:
		pay_frame = pandas.DataFrame(lnreq['payment_route']['hops'])
		pay_frame
		pay_frame['alias'] = pay_frame.apply(lambda x: getAlias(x.pub_key), axis=1)
		pay_frame
		return pay_frame
	except KeyError as e:
		print(f"Error: payment_error {lnreq['payment_error']}")
		return lnreq

def rebalance_script():
	a = listChannels()
	a = a[a['active'] == True]
	pl = []
	bcount = 0
	while len(a[a['local_balance'] < 500000]) > 0:
		a = listChannels()
		a = a[a['active'] == True]
		taker = a['tobalance'].idxmax()
		giver = a['tobalance'].idxmin()
		oid = a.loc[giver].chan_id
		pk = a.loc[taker].remote_pubkey
		# Divide it down to smaller chunks for cheaper fees
		pay_piece = int(a.loc[taker].tobalance/3)
		if pay_piece < 75000:
			pay_piece = int(a.loc[taker].tobalance)
		print(f'Sending {pay_piece} from {a.loc[giver].alias} to {a.loc[taker].alias}!')
		result = rebalance(pay_piece,oid,pk,4500,forced=True)
		pl.append(result)
		bcount += 1
		print(f'Rebalanced {bcount} times!')
	return pl
	
def inflows():
	a = getForwards(60)
	in_oids = a['chan_id_in'].unique()
	df = pandas.DataFrame()
	for edge in in_oids:
		try:
			df = df.append(getChanPolicy(edge))
		except Exception as e:
			print(f'Edge Not Found: {e}')
	df = df.reset_index()
	df = df.drop(['index'],axis=1)
	return df[df['pubkey'] != getMyPk()]


def outflows():
	a = getForwards(60)
	out_oids = a['chan_id_out'].unique()
	df = pandas.DataFrame()
	for edge in out_oids:
		try:
			df = df.append(getChanPolicy(edge))
		except Exception as e:
			print(f'Edge Not Found: {e}')
	df = df.reset_index()
	df = df.drop(['index'],axis=1)
	return df[df['pubkey'] != getMyPk()]

def flowsort():
	c = listChannels()
	fin = inflows()
	fout = outflows()
	in_nodes = set(fin.pubkey)
	out_nodes = set(fout.pubkey)
	routing_nodes = in_nodes.intersection(out_nodes)
	in_nodes = in_nodes - routing_nodes
	out_nodes = out_nodes - routing_nodes
	c[c['remote_pubkey'].isin(list(routing_nodes)) ]
	return in_nodes, routing_nodes, out_nodes


def rebalance(amt,outgoing_chan_id,last_hop_pubkey,fee_msat=4200, forced=False):
	if not forced:
		accept = input(f'Rebalancing chan id: {outgoing_chan_id} --> {getAlias(last_hop_pubkey)}. Press: (y/n)')
		if accept == 'y':
			pass
		else:
			print('Rebalance canceled.')
			return None, 0, None


	payreq = addInvoice(amt,'balance1')['payment_request']
	endpoint = '/v1/channels/transactions'
	bdata = {}
	bdata['fee_limit'] = {'fixed_msat': fee_msat}
	bdata['outgoing_chan_id'] = f'{outgoing_chan_id}'
	bdata['allow_self_payment'] = True
	bdata['last_hop_pubkey'] = base64.b64encode(bytes.fromhex(last_hop_pubkey)).decode()
	bdata['payment_request'] = payreq

	print(bdata)
	# return bdata
	# lnreq = sendPostRequest(url,data=bdata,debug=True)

	url = base_url + endpoint
	start = datetime.now()
	lnreq = requests.post(url, headers=headers, verify=cert_path, data=json.dumps(bdata))
	end = datetime.now()
	data = lnreq.json()
	print(data)
	if data['payment_error'] != '':
		print("payment error")
		data['payment_error'].split('\n')[0]
		# Unsuccessful so costs 0 sats
		tf = 0
	else:
		hops = pandas.DataFrame(data['payment_route']['hops'])
		print(hops.columns)
		hops['alias'] = hops.apply(lambda x: getAlias(x.pub_key), axis=1)
		print(hops[['alias','chan_id', 'chan_capacity', 'expiry', 'amt_to_forward_msat', 'fee_msat', 'pub_key']])
		print(hops.dtypes)
		print(hops.columns)
		tf = int(data['payment_route']['total_fees_msat'])/1000

	dur = (end-start).total_seconds()
	print(f'Total Routing Fees: {tf}')
	print(f'Payment Duration: {dur}')
	return tf,dur,lnreq


def listBalanceChannels(cid_list):
	a = listChannels()
	b = a.sort_values(by=['tobalance'])
	c = b['chan_id'].to_frame()
	# c.to_frame()
	ilist = []
	# Get index of rows we want to ignore
	for idx, row in c.iterrows():
		print(row[0])
		print(idx)
		if row[0] in cid_list:
			ilist.append(idx)

		# Drop indices
	d = b.drop(ilist)
	return d
	# AUTO BALANCE SCRIPT!
	# a[a['balanced'] > 0.5].apply(lambda x: rebalance(int(x['tobalance']),x['chan_id'],"032c17323caa51269b5124cf07a0c03772587ad8199e692cc3aae8397454367d34",4200),axis=1)




def PayByRoute(route,pay_hash=None):
	url = '/v1/channels/transactions/route'
	if pay_hash == None:
		pay_hash = base64.b64encode(b'blah1234').decode()
	else:
		pay_hash = base64.b64encode(pay_hash.encode('UTF-8')).decode()
	data = { 
		'payment_hash': pay_hash, 
		'route': route, 
	}
	lnreq = sendPostRequest(url,data)
	pprint(lnreq)
	return lnreq

def getNewAddress():
	url = '/v1/newaddress'
	lnreq = sendGetRequest(url)
	return lnreq['address']


def getChanPoint(chanid):
	url = f'/v1/graph/edge/{chanid}'
	lnreq = sendGetRequest(url)
	cp = lnreq['chan_point']
	return cp

def getPendingChannels():
	url = '/v1/channels/pending'
	lnreq = sendGetRequest(url)
	pending_types = list(set(lnreq.keys()) - {'total_limbo_balance'})
	pending_types
	print(lnreq)
	a = pandas.DataFrame(lnreq['pending_open_channels'])
	print(a)
	# for pend in pending_types:
	# 	b = pandas.DataFrame(lnreq[pend][0]['channel'], index=[0])[['remote_node_pub', 'channel_point', 'capacity','local_balance']]
	# 	type_list = pend.split("_")
	# 	b['type'] = type_list[1]
	# 	a = a.append(b)
	# a['alias'] = a['remote_node_pub'].apply(lambda x: getAlias(x))
	return a

# a = pandas.DataFrame(lnreq['pending_open_channels'][0]['channel'], index=[0])[['remote_node_pub', 'channel_point', 'capacity','local_balance']]
# a['type'] = 'open'
# b = pandas.DataFrame(lnreq['pending_force_closing_channels'][0]['channel'], index=[0])[['remote_node_pub', 'channel_point', 'capacity','local_balance']]
# b['type'] = 'force_close'
# c = a.append(b)

# ****** GRAPH ******
def describeGraph():
	url = '/v1/graph'
	lnreq = sendGetRequest(url)
	return lnreq

def getMyEdges():
	graph = describeGraph()
	edges = graph['edges']
	eframe = pandas.DataFrame(edges)
	mpk = getMyPk()
	myedges = eframe.query(f'node1_pub.str.contains("{mpk}") | node2_pub.str.contains("{mpk}")')
	return myedges


# ****** FEE INFO ******
def updateChanPolicy(fee_rate=0.000001,base_fee_msat='300'):
	url = '/v1/chanpolicy'
	data = {
		'global': True,
		'time_lock_delta': 14,
		'min_htlc_msat': 1,
		'min_htlc_msat_specified': True,
		'fee_rate': fee_rate,
		'base_fee_msat': base_fee_msat,
		}
	lnreq = sendPostRequest(url,data)
	print(lnreq)
	return lnreq

def feeReport():
	url = '/v1/fees'
	lnreq = sendGetRequest(url)
	fee_frame = pandas.DataFrame(lnreq['channel_fees'])
	return fee_frame

# ****** CHANNEL ******
def getChanPolicy(chanid, pubkey=None, npk=None):
	url = '/v1/graph/edge/{}'
	lnreq = sendGetRequest(url,str(chanid) )
	df = pandas.DataFrame.from_dict({lnreq['node1_pub']:lnreq['node1_policy'],lnreq['node2_pub']:lnreq['node2_policy']})
	df = df.T
	df.reset_index(inplace=True)
	df.rename(columns={'index':'pubkey'}, inplace=True)
	df['alias'] = df['pubkey'].apply(lambda x: getAlias(x))
	# If things are null it doesnt return them!!
	df = df.fillna(0)
	# Only get info for one side of channel
	if pubkey:
		print("Including PK")
		b = df[df.pubkey == pubkey]
		return b
	# Get info excluding one side
	elif npk:
		print("Excluding PK")
		b = df.query(f'pubkey != "{npk}"')
		return b
	# print(df)
	return df

def getChannelDisabled(cid,mypk=None):
	# Build in optimization if PK is handy
	cframe = getChanPolicy(cid)
	if mypk == None:
		mypk = getMyPk()
	print(mypk)
	d = cframe[cframe['pubkey'] != mypk]
	# Get only remaining item left
	print(d)
	index = list(set(d.index))[0]
	print(index)
	cstate = d.loc[int(index),'disabled']
	return cstate


def getBalance(row):
	return row['local_balance'] / (row['local_balance']+row['remote_balance'])

# def getToBalance(row):
# 	return (row['balanced']-0.5) * (row['local_balance']+row['remote_balance'])

def getToBalance(row,target=500000):
	return target-row['local_balance']

def listChannels(chanpoint=None,all=False,disabled=False):
	url = '/v1/channels'
	lnreq = sendGetRequest(url)
	# print(lnreq)
	d = pandas.DataFrame(lnreq['channels'])
	y = d[['active','chan_id','channel_point','remote_pubkey','local_balance','remote_balance']].fillna(0)
	# Convert columns to integers
	y[['local_balance','remote_balance']] = y[['local_balance','remote_balance']].apply(pandas.to_numeric, errors='coerce')
	y['balanced'] = y.apply(getBalance, axis=1)
	y['alias'] = y.apply(lambda x: getAlias(x.remote_pubkey), axis=1)
	y['tobalance'] = y.apply(getToBalance, axis=1)
	# y = y.sort_values(by=['balanced'])
	y = y.sort_values(by=['local_balance'])
	# y = y.sort_values(by=['balanced'])
	# Get balance ratio of all channels
	rb = y['remote_balance'].sum()
	lb = y['local_balance'].sum()
	print(f'Local to remote balance ratio: {lb/(lb+rb)}')
	# y = y.set_index("channel_point")
	if disabled:
		pk = getMyPk()
		y['d_cp'] = y.apply(lambda x: getChannelDisabled(x,pk), axis=1)
	if chanpoint:
		y = y[y.index==chanpoint]
	if all:
		return y
	else:
		return y[['active','alias','balanced','tobalance','local_balance','remote_balance','chan_id','remote_pubkey']]

def connectPeer(ln_at_url):
	url = '/v1/peers'
	pubkey,host = ln_at_url.split('@')
	data = { 
		'addr': {'pubkey': pubkey,'host': host}
	}
	lnreq = sendPostRequest(url,data)
	return lnreq

def toSats(btcs):
	return int(btcs*100000000)

def openChannel(ln_at_url,sats,fee=1,suc=False):
	url = '/v1/channels'
	# apk = f'{pk}'.encode('UTF-8')
	print(connectPeer(ln_at_url))
	pubkey,host = ln_at_url.split('@')
	# 'node_pubkey_string': f'{pk}',
	data = {
		'node_pubkey_string': f'{pubkey}',
		# This doesnt work but theoretically this is the better way
		# 'node_pubkey': base64.b64encode(bytes.fromhex(pubkey)).decode(),
		'spend_unconfirmed': suc,
		'local_funding_amount':f'{sats}',
		'sat_per_byte': f'{fee}'
		}
	print(data)
	lnreq = sendPostRequest(url,data)
	# if 'error' in lnreq.keys():
	# pprint(lnreq)
	try:
		tx_b64 = base64.b64decode(lnreq['funding_txid_bytes'])
		# KEY STEP: You have to reverse the byte order be able to look it up on an explorer
		txid = codecs.encode(bytes(reversed(tx_b64)),'hex')
		print(f"TXID: hex --> { txid } default --> {lnreq['funding_txid_bytes']}\n")
		return txid
	except KeyError:
		error = lnreq['error']
		print(f"ERROR OPENING CHANNEL:\n\n{error}")
		# Parse out the numbers in the failure, and do something with it
		# d = [float(i) for i in list(map(lambda x: x if x.replace('.', '', 1).isdigit() else print(x),error.split(' '))) if i ]
		# d = list(map(lambda x: int(x*100000000), d))
		print("Unable to openchannel, amount error:")
		f = tuple([toSats(float(s)) for s in error.split() if s.replace('.', '', 1).isdigit() ])
		print(f)
		dif = f[0] - f[1]
		print(dif)
		chan_size_w_fee = sats - dif
		print(f'Transaction requires {dif} sats Fee. Try a smaller channel size {chan_size_w_fee} next time to use {fee} sat/byte!\n' )
		# print(d)
		# print(d[0]-d[1])
		return error


def streamInvoices():
	url = base_url + '/v1/invoices/subscribe'
	r = requests.get(url+'?add_index=1', stream=True, headers=headers, verify=cert_path)
	for line in r.iter_lines():
		a = json.loads(line.decode("UTF-8"))
		print(a)

# Channel Point to Channel Id
def CP2CID(chan_point, chan_list):
	chan_list.reset_index(inplace=True)
	a = chan_list[channel_point==chan_point]
	return a.chan_id
# need channel point to chan_id
# Stuck here
def listChanFees(chan_id=None):
	lnreq = sendGetRequest(url14)
	z = pandas.DataFrame(lnreq['channel_fees'])
	z = z.rename(columns={'chan_point':'channel_point'})
	# z = z.set_index("channel_point")
	clist = listChannels()
	clist = clist.rename(columns={'remote_pubkey':'pubkey'})
	# z['chan_id'] = z['channel_point'].apply(lambda x: CP2CID(x,clist) )
	b = getChanPolicy(clist.iloc[0,:].chan_id,clist.iloc[0,:].remote_pubkey)
# getChanPolicy(a.iloc[0,:].chan_id,)
	print(b)
	c = b.join(z)
	# x = chan_info.join(z).fillna(0)
	return c


# System Functions
def getInfo(frame=False):
	url = '/v1/getinfo'
	lnreq = sendGetRequest(url)
	print(lnreq)
	if frame:
		lnframe = pandas.DataFrame(lnreq)
		return lnframe
	return lnreq

def getMyPk():
	info = getInfo()
	mypk = info['identity_pubkey']
	return mypk
	
def getBlockHeight():
	return getInfo()['block_height']
	# return sendGetRequest(url2)['block_height']

def getMyPK():
	return getInfo()['identity_pubkey']


def getAlias(pubkey,index=True):
	try:
		# Attempt to use index names first
		alias = pkdb[pubkey]
		return alias
	except KeyError as e:
		lnreq = getNodeInfo(pubkey)
		alias = lnreq['node']['alias']
		pkdb.update({pubkey: alias})
		return lnreq['node']['alias']
	except KeyError as e:
		print(f"{pubkey} doesn't have an alias? Error: {e}")
		return "NONE?"

def getNodeInfo(pubkey,channels=False):
	url = '/v1/graph/node/{}'
	if channels:
		url = url + '?include_channels=true'
	lnreq = sendGetRequest(url,pubkey)
	try:
		return lnreq
	except KeyError as e:
		print(f"{pubkey} doesn't have an alias? Error: {e}")
		return "NONE?"

def decodePR(pr):
	url = '/v1/payreq/{}'
	lnreq = sendGetRequest(url,pr)
	return lnreq

# Receiving Functions
def addInvoice(amt,memo):
	url = '/v1/invoices'
	data = {'memo':memo,'value':amt}
	lnreq = sendPostRequest(url,data)
	return lnreq

def lookupInvoice(invoice_rhash):
	lnreq = sendGetRequest(f'/v1/invoice/{invoice_rhash}')
	return lnreq

def lookupInvoice2(invoice_rhash):
	lnreq = sendGetRequest(f'/v1/invoice/',data=invoice_rhash)
	return lnreq

def listInvoices(max_invs=1000):
	url = '/v1/invoices'
	lnreq = sendGetRequest(url+f"?num_max_invoices={max_invs}")
	df = pandas.DataFrame(lnreq['invoices'])
	print("Available Data Columns: ")
	print(df.columns)
	df = df.fillna('0')
	print(df[['memo','amt_paid_sat','state','settled','creation_date','settle_date','r_preimage']])
	df['creation_date_h'] = df.apply(lambda x: datetime.fromtimestamp(int(x['creation_date'])) if int(x['settle_date']) != 0 else 0, axis=1 )
	df['settle_date_h'] = df.apply(lambda x: datetime.fromtimestamp(int(x['settle_date'])) if int(x['settle_date']) != 0 else 0, axis=1 )
	
	# df['alias'] = Series(b).apply(lambda x: getAlias(x), axis=1 )
	# b= list(a.index)
	base_columns = ['memo','creation_date_h','state','settled','settle_date_h','amt_paid_sat','amt_paid_msat']
	
	return df[base_columns]
	# return df[['memo','amt_paid_sat','state','creation_date_h','settle_date_h','htlcs']]
	# datetime.fromtimestamp(x['creation_date'])

def showFunds():
	chain_funds_url = '/v1/balance/blockchain'
	on = sendGetRequest(chain_funds_url)
	offchain_funds_url = '/v1/balance/channels'
	off = sendGetRequest(offchain_funds_url)

	data = {'on-chain':on,'off-offchain':off}

	print(f'On-Chain: {on}\t Off-Chain: {off}')
	print(data)
	funds_frame = pandas.DataFrame(data)
	return funds_frame


def addFees(hop,fee_msat):
	hop['fee_msat'] = str(fee_msat)
	hop['fee'] = str(floor(int(fee_msat)/1000))
	print(getAlias(hop['pub_key']) )	
	pprint(hop)
	return hop

def addForwardandFees(route):
	num_hops = len(route['hops'])
	base_fee = 20100
	# fee_hops = num_hops - 1
	fee_hops = num_hops
	# No fee on last hop
	route['total_fees_msat'] = str( fee_hops * base_fee )
	route['total_fees'] = str( floor(int(route['total_fees_msat']) / 1000) ) 
	route['total_amt_msat'] = str( int( route['total_amt_msat']) + int( route['total_fees_msat'] ) )
	route['total_amt'] = str( floor(int( route['total_amt_msat'])/ 1000 ) )
	# del route['hops'][fee_hops][]
	pprint(route)
	# Iterate of hops and add fees
	hoplist = []
	bh = getBlockHeight()
	# tl = route['total_time_lock']
	tl_delta_total = bh
	max_tld = 0
	# route['hops'].reverse()
	time_lock = bh
	for hop in route['hops']:
		# Update fees on hop object
		ahop = addFees(hop,base_fee)
		tl_delta_total += 10

		# Figure out time lock delta
		pk = hop['pub_key']
		cid = hop['chan_id']
		ln = getChanPolicy(cid)

		if ln['node1_pub'] == pk:
			policy = ln['node1_policy']
		elif ln['node2_pub'] == pk:
			policy = ln['node2_policy']	

		# Determine max time lock of all the hops
		tld = policy['time_lock_delta']
		time_lock += tld
		# if tld > max_tld:
		# 	max_tld = tld
		# 	print(f"Found Higher Max TLD: {max_tld}")

		ahop['expiry'] = time_lock
		hoplist.append(ahop)

		

	# Override hoplist with hops with fees
	# hoplist.reverse()
	route['hops'] = hoplist
	route['total_time_lock'] = time_lock
	return route
	# hoplist = []
	# for hop in route['hops']:
	# 	hop
		

# def getForwards(start,end):
def getForwards(days_past=30):
	start = int( (datetime.now() - timedelta(days=days_past)).timestamp() )
	end = int( datetime.now().timestamp() )
	data = { 'start_time': start, 'end_time': end,'num_max_events':2000 }
	url = '/v1/switch'
	lnreq = sendPostRequest(url,data)
	fwd_frame = pandas.DataFrame(lnreq['forwarding_events'])
	# Convert Timestamp to nice datetime
	fwd_frame['dt'] = fwd_frame['timestamp'].apply(lambda x: datetime.fromtimestamp(int(x)) )
	fwd_frame['dts'] = fwd_frame.dt.astype('str')
	print(f'Number of Satoshi Made This Month: {pandas.to_numeric(fwd_frame["fee_msat"]).sum()/1000}!')
	print(f'AVG Number of Satoshi Made Per Day: {pandas.to_numeric(fwd_frame["fee_msat"]).sum()/1000/days_past}!')
	return fwd_frame

def fwdsToday(ff):
	fwds = ff.query(f'dts.str.contains("{datetime.now().strftime("%Y-%m-%d")}")').shape[0]
	return fwds

# for i in range(30,-1,-1):
# 	fwdsStats(a,i)
def fwdsStats(ff,days_ago=0):
	day_str = (datetime.now()-timedelta(days=days_ago)).strftime("%Y-%m-%d")
	day_fwds = ff.query(f'dts.str.contains("{day_str}")')
	day_fwds_count = ff.query(f'dts.str.contains("{day_str}")').shape[0]
	avg_fees = day_fwds.fee_msat.astype('float').mean()
	avg_forward = day_fwds.amt_in.astype('float').mean()
	return {'event_day':day_str, 'count':day_fwds_count, 'avg_fees':avg_fees, 'avg_forward':avg_forward}

def fwdByDay(ff,days_past=30):
	# datetime.strptime('2020-04-04','%Y-%m-%d')
	t = datetime.now().date() - timedelta(days_past)
	t.strftime('%Y-%m-%d')
	results = []
	# TODO: look into this logic a bit
	for i in range(0,days_past+1):
		num_fwds = ff.query(f'dts.str.contains("{t.strftime("%Y-%m-%d")}")').shape[0]
		results.append((t.strftime("%Y-%m-%d"),num_fwds))
		t += timedelta(days = 1)
	rframe = pandas.DataFrame(results)
	return rframe



# fix me, and figure out arrays!
def queryRoute(src_pk, dest_pk, oid=None, lh=None, pay_amt=123, ignore_list=None, frame=False):
	# base64.b64encode(bytes.fromhex(last_hop_pubkey)).decode()
	c = listChannels()
	c['pk64'] = c['remote_pubkey'].apply(lambda x: base64.urlsafe_b64encode(bytes.fromhex(x)).decode())
	# outgoing_chan_id
	# last_hop_pubkey
	# Convert HEX pubkeys to to base64
	for node in ignore_list:
		ig64 = base64.b64encode(bytes.fromhex(node)).decode().replace('+','-').replace('/','_')
		id_url_safe = ignore
		id_percent_encoded = urllib.parse.quote(id_url_safe)
	target_url = f"/v1/graph/routes/{dest_pk}/{pay_amt}?source_pub_key={src_pk}"
	target_url += f"&use_mission_control=true&final_cltv_delta=144&fee_limit.fixed_msat=44000"
	# target_url + f"&ignored_nodes="
	if lh:
		target_url + f"&last_hop_pubkey={lh}"
	if oid:
		target_url + f"&outgoing_chan_id={oid}"
	lnreq = sendGetRequest(target_url)
	if frame:
		f = lnreq['routes'][0]
		f['total_fees_msat'] = '0'
		f['total_fees'] = '0'
		return f
	hops = lnreq['routes'][0]['hops']
	hoplist = []
	for hop in hops:
		hoplist.append(hop)
	# It only ever returns 1 route
	return lnreq['routes'][0]['hops']

def buildCheapRoute():
	a = getNodeInfo('03295d2e292565743a40bd44da227a820f8730877bc3dfadebade8785bcf355258',True)
	b = pandas.DataFrame(a['channels'])
	# c = b.channel_id[0:10].apply(lambda x: getChanPolicy(x,npk='03295d2e292565743a40bd44da227a820f8730877bc3dfadebade8785bcf355258'))
	d = pandas.DataFrame()
	for i in b.index[0:50]:
		cid = b.loc[i,'channel_id']
		e = getChanPolicy(cid,npk='03295d2e292565743a40bd44da227a820f8730877bc3dfadebade8785bcf355258')
		print(e)
		d = d.append(e)

	d.sort_values(['fee_rate_milli_msat','fee_base_msat'],ascending=[True,False])
# '029a8741675c4c9078b577ddc4348d602d2fb45a12e6087b617925997a84f4c02e'

def routeSetExpiry(hf):
	hf['alias'] = hf['pub_key'].apply(lambda x: getAlias(x) )
	# Store original df
	hf_base = hf.copy()
	# Remove final hop from frame
	hf = hf.head(len(hf)-1)
	# reverse order because first hop has longest expiry
	# hf = hf[::-1]
	# hf.at[len(b)-1,'expiry'] = getBlockHeight() + getChanPolicy(hf.iloc[0]['chan_id'],hf.iloc[0]['pub_key']).iloc[0]['time_lock_delta']
	# print(f'Current Block Height {getBlockHeight()}')
	# chan_fee_info = getChanPolicy(b.iloc[len(b)-1]['chan_id'], b.iloc[len(b)-1]['pub_key'])
	# hf.at[len(b)-1,'expiry'] = getBlockHeight() + chan_fee_info['time_lock_delta']
	# hf.at[len(b)-2,'expiry'] = hf.at[len(b)-1,'expiry'] + chan_fee_info['time_lock_delta']
	# Dont do last hops
	first = True
	for i in range(len(hf)-1, -1,-1):
		print(f"Hop Index:{i} {getAlias(hf.at[i,'pub_key'])}")
		chan_fee_info = getChanPolicy(hf.at[i,'chan_id'], hf.at[i,'pub_key'])
		if first:
			first = False
			hf.at[i,'expiry'] = getBlockHeight() + chan_fee_info.iloc[0]['time_lock_delta']
		else:
			hf.at[i,'expiry'] = hf.at[i+1,'expiry'] + int(chan_fee_info.iloc[0]['time_lock_delta'])

	hf = hf.append(hf_base.tail(1))
	hf.at[len(hf)-1,'expiry'] = hf.at[len(hf)-2,'expiry']
		# try:
		# 	hf.at[i,'expiry'] = hf.iloc[index+1]['expiry'] + int(chan_fee_info['time_lock_delta'])
		# except IndexError as e:
		# 	print("Out of bounds") #, use current height!")
			# hf.at[index,'expiry'] = getBlockHeight() + int(chan_fee_info['time_lock_delta'])
	return hf

def routeSetFees(hf):
	# Reset Frames Fees
	hf['fee_msat'] = 0
	hf['fee_sat'] = 0
	pay_amt_msat = hf.iloc[0]['amt_to_forward_msat']
	# No fee for last hop
	for i in range(len(hf)-2, -1,-1):
		chan_fee_info = getChanPolicy(hf.at[i,'chan_id'], hf.at[i,'pub_key'])
		print(chan_fee_info)
		# Calculate fee for each hop
		msats =  floor( int(chan_fee_info.iloc[0]['fee_rate_milli_msat'])/1000000 * 
			int(hf.at[i,'amt_to_forward'])/1000 + 
			int(chan_fee_info.iloc[0]['fee_base_msat']) 
		)
		hf.at[i,'fee_msat'] = 13000													
		hf.at[i,'fee_sat'] = floor(hf.at[i,'fee_msat']/1000)
		# hf.at[i,'fee_msat'] = msats															
		# hf.at[i,'fee_sat'] = floor(msats/1000)
	for i in range(len(hf)-1, -1,-1):
		try:
			hf.at[i,'amt_to_forward_msat'] = int(hf.at[i+1,'amt_to_forward_msat']) + int(hf.at[i,'fee_msat'])
		except KeyError:
			hf.at[i,'amt_to_forward_msat'] = int(pay_amt_msat) + int(hf.at[i,'fee_msat'])
		hf.at[i,'amt_to_forward'] = floor(hf.at[i,'amt_to_forward_msat']/1000)
	print(hf[['fee_sat','fee_msat','amt_to_forward','amt_to_forward_msat']])

	hf['fee'] = hf['fee_sat']
	return hf
	# col = list(set(hf.columns) - set(['fee']))
	# return hf[col]

def hopFrame(hops):
	# Create Frame
	hframe = pandas.DataFrame(hops)
	# Make sure this has a value, for some reason API doesnt return anything if false
	hframe['tlv_payload'] = hframe['tlv_payload'].fillna(False)

	# Add fee columns
	if "fee_msat" not in list(hframe.columns):
		hframe.insert(1,'fee_msat','0')
	if "fee_sat" not in list(hframe.columns):
		hframe.insert(1,'fee_sat','0')

	# Store original hop dataframe
	hframe_base = hframe
	# Reverse order
	# hframe = hframe.iloc[::-1]
	# policy = pandas.DataFrame()
	# Get policy for first hop
	# policy = policy.append()
	# for index, row in hframe.iterrows():
	# 	policy = policy.append(getChanPolicy(row['chan_id'],row['pub_key']))

	# policy = policy.fillna(0)
	# policy = policy.rename(columns={'pubkey':'pub_key'})
	# hframe = hframe.merge(policy,on='pub_key')
	return hframe


# ON-CHAIN
def listChainTxns(show_columns=False,add_columns=None):
	url = '/v1/transactions'
	lnreq = sendGetRequest(url)
	lnframe = pandas.DataFrame(lnreq['transactions'])
	lnframe['ts_h'] = lnframe.apply(lambda x: datetime.fromtimestamp(int(x['time_stamp'])), axis=1 )
	default_columns = ['ts_h','num_confirmations','amount','tx_hash','total_fees']
	if add_columns != None:
		default_columns = default_columns + add_columns
	if show_columns:
		print(lnframe.columns)

	return lnframe[default_columns]

def sendCoins(addr,amt,toself=True):
	url = '/v1/transactions'
	if toself:
		addr = getNewAddress()
	# either target_conf or sat_per_byte used at one time
	data = { 
		# 'target_conf': 20,
		'sat_per_byte': 5, 
		'send_all': False, 
		'addr': f'{addr}', 
		'amount': f'{amt}',
		'spend_unconfirmed': True
	}
	lnreq = sendPostRequest(url,data)
	return lnreq

def closeChannel(channel_point,output_index=0,force=False):
	url = f'/v1/channels/{channel_point}/{output_index}?force={force}'
	query = {
		'force':force,
		'sat_per_byte':'1'
	}
	# ,query
	x = sendDeleteRequest(url)
	return x
	# DELETE /v1/channels/{channel_point.funding_txid_str}/{channel_point.output_index}

def listCoins(min_confs=0,show_columns=False,add_columns=None):
	# url = f'/v1/utxos?min_confs={min_confs}'
	url = f'/v1/utxos'
	lnreq = sendGetRequest(url)

	print(f'Received message: {pformat(lnreq)}')
	# Guard Clause
	if 'utxos' not in lnreq.keys():
		print('No UTXOs available')
		return

	lnframe = pandas.DataFrame(lnreq['utxos'])

	default_columns = ['address_type','address','amount_sat','confirmations']
	if add_columns != None:
		default_columns = default_columns + add_columns
	if show_columns:
		print(lnframe.columns)
	return lnframe[default_columns]


def blahroute():
	# # def buildRoute():
	# # 	# Destination pubkey
	# whenbtc --> lnbig
	# Hop1
	hoplist = []
	pay_amt = 5000

	dest_pub_key = creampay
	src_pub_key = my_key
	target_url = url15.format(pub_key=dest_pub_key,amt=pay_amt) + f"?source_pub_key={src_pub_key}&use_mission_control=false&final_cltv_delta=144"
	target_url
	lnreq = sendGetRequest(target_url)
	hops = lnreq['routes'][0]['hops']
	for hop in hops:
		hoplist.append(hop)

	dest_pub_key = bitrefill
	src_pub_key = creampay
	target_url = url15.format(pub_key=dest_pub_key,amt=pay_amt) + f"?source_pub_key={src_pub_key}&use_mission_control=false&final_cltv_delta=144"
	target_url
	lnreq = sendGetRequest(target_url)
	hops = lnreq['routes'][0]['hops']
	for hop in hops:
		hoplist.append(hop)


	dest_pub_key = lnbig
	src_pub_key = bitrefill
	target_url = url15.format(pub_key=dest_pub_key,amt=pay_amt) + f"?source_pub_key={src_pub_key}&use_mission_control=false&final_cltv_delta=144"
	target_url
	lnreq = sendGetRequest(target_url)
	hops = lnreq['routes'][0]['hops']
	for hop in hops:
		hoplist.append(hop)

	dest_pub_key = my_key
	src_pub_key = lnbig
	target_url = url15.format(pub_key=dest_pub_key,amt=pay_amt) + f"?source_pub_key={src_pub_key}&use_mission_control=false&final_cltv_delta=144"
	target_url
	lnreq = sendGetRequest(target_url)
	hops = lnreq['routes'][0]['hops']
	for hop in hops:
		hoplist.append(hop)

	# Add fees in sat and msat manually?? 
	# hoplist = lambda x


	hop_frame = pandas.DataFrame(hoplist)
	hop_frame = hop_frame.rename(columns={'pub_key':'remote_pubkey'})
	hop_frame['alias'] = hop_frame.apply(lambda x: getAlias(x.remote_pubkey), axis=1)

	hop_frame



	# hops_fees = [addFees(hop) for hop in hoplist] 
	send_route = lnreq['routes'][0]


	# Uses routes object, but add all hops
	send_route['hops'][:] = []
	send_route['hops'] = hoplist



	# send_route = addForwardandFees(send_route)
	pprint(send_route)



	# chan_info = getChannelBalance()
	# balances = chan_info[['alias','chan_id','balanced','local_balance','remote_balance']]
	# balances


	# invoice = createInvoice(pay_amt,'rebalance test')
	# pay_hash = decodePR(invoice['payment_request'])['payment_hash']

	# reverse order of hops
	# send_route['hops'].reverse()

	return send_route
	# lnreq = PayByRoute(send_route)
	# lnreq

if __name__ == "__main__":
	print(listChannels())
	code.interact(local=locals())




# Start at pubkey of node to rebalance
# Set Source their and dest to bitrefill
# Set Source of bitrefill to dest target node

# bosworth
# longest expiry, first hop
# last hop isnt really hop at all, its the destination

# The expiry is about when you get your outbound funds back but the last hop has no outbound funds
# Yeah like if you pay a direct peer some money there is no compensation necessary for forwarding
# fractions of a msat: rounded down

# roasbeef
# if the last node gets a CLTV of 40, and the onion says it should be 50, then they’ll reject the HTLC
# we send the information twice basically: what the penultimate node shoudl extend, and what the final node should receive

