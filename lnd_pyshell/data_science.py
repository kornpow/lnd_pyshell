from lnd_rest import *
import code
import pandas
import pyqrcode

pandas.set_option('display.max_colwidth', None)
pandas.set_option('display.max_rows', None)

qrdata = getNewAddress()
print(f'Creating code for address: {qrdata}')
qr = pyqrcode.create(qrdata)
print(qr.terminal(quiet_zone=1))

print(pyqrcode.create(''.upper(),version=17,mode='alphanumeric').terminal(quiet_zone=1))

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
		result = rebalance(pay_piece,oid,pk,5000,force=True)
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

def findBadNodes():
a = getForwards()
forwarding_nodes = set(a.tail(500).chan_id_in).union(set(a.tail(500).chan_id_out))
all_chan_ids = set(listChannels().chan_id)
bad_node_ids = all_chan_ids.difference(forwarding_nodes)
badnodelist = listChannels(all=True).query("chan_id.isin(@bad_node_ids)")

def test1():
	a = getForwards()
	fwd_in = list(a.query("dts.str.contains('2020-07-13')").chan_id_in)
	fwd_out = list(a.query("dts.str.contains('2020-07-13')").chan_id_out)
	print("In-Nodes: ")
	listChannels().query("chan_id.isin(@fwd_in)")
	print("Out-Nodes: ")
	listChannels().query("chan_id.isin(@fwd_out)")


depleted = listChannels().query("local_balance < 400000 and active == True and capacity > 1000000")
num_depleted = depleted.shape[0]

glut = listChannels().query("remote_balance < 400000 and active == True and capacity > 1000000")
num_glut = glut.shape[0]

oid = 
lh = 
rebalance(100000,oid,lh,8000,force=True)

def rebalance_alg():
cycles = 0
total_routing_fees = 0
while cycles < 10:
	# Depleted channels
	depleted = listChannels().query("local_balance < 400000 and active == True and capacity > 1000000")
	num_depleted = depleted.shape[0]
	# Full channels
	glut = listChannels().query("remote_balance < 400000 and active == True and capacity > 1000000")
	num_glut = glut.shape[0]
	print(f'{num_glut} glut--> {num_depleted} depleted')
	source = glut.sample(1)
	dest = depleted.sample(1)
	print(f'{source.alias.item()} ---> {dest.alias.item()} ')
	a,b,c,d = rebalance(100000,source.chan_id.item(),dest.remote_pubkey.item(),8000,force=True)
	total_routing_fees += a
	error = c.json()['payment_error']
	print(f'Payment Response: {error}')
	print(f'Total Routing Fees: {total_routing_fees}')
	if error == '':
		cycles += 1
		print('Successful route')
		looper = 0
		while error == '':
			a,b,c,d = rebalance(100000,source.chan_id.item(),dest.remote_pubkey.item(),8000,force=True)
			error = c.json()['payment_error']
			total_routing_fees += a
			looper += 1
			if looper == 2:
				break


elif error == 'no_route' or error == 'insufficient_balance':
elif error == 'timeout':
else:
	print("unknown error")

def rebalancePartners():
	partners = []
	mypk = getMyPK()
	hop1_partners = getNodeChannels(mypk)
	count = 0
	for z in hop1_partners.iterrows():
		hop1_pk = z[1].item()
		hop2_partners = getNodeChannels(hop1_pk)
		for y in hop2_partners.iterrows():
			hop2_pk = y[1].item()
			hop3_partners = getNodeChannels(hop2_pk)
			for x in hop3_partners.iterrows():
				hop3_pk = x[1].item()
				count += 1
				print(f'Searched {count} nodes')
				if hop3_pk == mypk:
					partners.append((hop1_pk, hop2_pk, hop3_pk))
	return partners

fh_pk = '031d2bbc75802689312220a017c6b51fa246efc59c7aa9355f6f7395038ffb4d6a'
lh_pk = '02f3069a342ae2883a6f29e275f06f28a56a6ea2e2d96f5888a3266444dcf542b6'

# disabled == False and 
def rebalancePartners2():
partners = []
mypk = getMyPK()
fh_pk = ''
hop1_partners = getNodeChannels2(mypk)
# hop1_partners = hop1_partners.query("fee_rate_milli_msat < 15").head(100)
count = 0
lh_pk = '021c97a90a411ff2b10dc2a8e32de2f29d2fa49d41bfbb52bd416e460db0747d0d'
for z in hop1_partners.pubkey.values:
	# print(z)
	hop1_pk = z
	try:
		hop2_partners = getNodeChannels2(hop1_pk)
		hop2_partners = hop2_partners.query("fee_rate_milli_msat < 5").head(100)
		# print(hop2_partners)
	except Exception as e:
		continue
	for y in hop2_partners.pubkey.values:
		try:
			# print(y)
			hop2_pk = y
			hop3_partners = getNodeChannels2(hop2_pk)
			hop3_partners = hop3_partners.query("fee_rate_milli_msat < 5").head(100)
			count += 1
			print(f'Searched {count} nodes')
			if mypk in hop3_partners.pubkey.values and hop2_pk == lh_pk:
				print(getAlias(hop3_pk))
				partners.append((hop1_pk, hop2_pk, mypk))
		except Exception as e:
			continue
		for x in hop3_partners.pubkey.values:
			try:
				# print(y)
				hop3_pk = x
				hop4_partners = getNodeChannels2(hop3_pk)
				hop4_partners = hop3_partners.query("fee_rate_milli_msat < 5").head(100)
				count += 1
				print(f'Searched {count} nodes')
				if mypk in hop4_partners.pubkey.values and hop3_pk == lh_pk:
					print(getAlias(hop3_pk))
					partners.append((hop1_pk, hop2_pk, hop3_pk, mypk))
			except Exception as e:
				continue


b = pandas.DataFrame(partners)
b.columns = ["one","two","three"]
b["oid"] = b.one.apply(lambda x: getAlias(x))
b["lh"] = b.two.apply(lambda x: getAlias(x))
hops  = list(b.iloc[0][['one','two','three']])
r = buildRoute(hops,100000)
invoice = addInvoice(100000,'test')
pprint(sendRoute(invoice['r_hash'],r))


invoice = addInvoice(balance_amt,'test')


oinv = openInvoices()
oinv.query("memo == 'balance'").sort_values("value_msat")


listChannels(all=True).query("capacity >= 1000000 and balanced > 0.8 and active == True")[["alias","chan_id","remote_pubkey","balanced"]]




import websockets
import asyncio
import ssl
import logging
logger = logging.getLogger('websockets')
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())

macaroon = codecs.encode(open(f'{LND_DIR}/data/chain/bitcoin/{CHAIN}/admin.macaroon', 'rb').read(), 'hex').decode()

headers = {'Grpc-Metadata-macaroon': macaroon}

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_verify_locations('/home/skorn/.lnd/tls.cert')

async def lc():
	ws = await websockets.connect("wss://10.0.0.111:8080/v2/wallet/address/next?method=POST", ping_timeout=None, ping_interval=1, ssl=ssl_context, extra_headers=headers, max_size=1000000000)
	await ws.send(json.dumps({}).encode('UTF-8'))
	hi = await ws.recv()
	print(hi)
	async for message in ws:
		print('receiving')
		try:
			hi = await asyncio.wait_for(ws.recv(), timeout=5)
			hi = json.loads(hi)
			# hi = hi['result']
			pprint(hi)
		except asyncio.TimeoutError:
			print('timeout!')
		except asyncio.CancelledError:
			print("cancelled?")

htlce = []
async def htlcevents1():
	ws = await websockets.connect("wss://10.0.0.111:8080/v2/router/htlcevents?method=GET", ping_timeout=None, ping_interval=1, ssl=ssl_context, extra_headers=headers, max_size=1000000000)
	# future = asyncio.run_coroutine_threadsafe(pinger(ws), loop)
	print('waiting')
	await asyncio.sleep(1)
	print('priming')
	await ws.send(json.dumps({}).encode('UTF-8'))
	while True:
		print('receiving')
		try:
			hi = await asyncio.wait_for(ws.recv(), timeout=5)
			hi = json.loads(hi)
			hi = hi['result']
			htlce.append(hi)
			pprint(hi)
		except asyncio.TimeoutError:
			print('timeout!')
		except asyncio.CancelledError:
			print("cancelled?")

htlce = []
async def htlcevents2():
	ws = await websockets.connect("wss://10.0.0.111:8080/v2/router/htlcevents?method=GET", ping_timeout=None, ping_interval=20, ssl=ssl_context, extra_headers=headers, max_size=1000000000)
	# future = asyncio.run_coroutine_threadsafe(pinger(ws), loop)
	print('waiting')
	await asyncio.sleep(1)
	print('priming')
	await ws.send(json.dumps({}).encode('UTF-8'))
	async for message in ws:
		print('receiving')
		try:
			hi = await asyncio.wait_for(ws.recv(), timeout=5)
			hi = json.loads(hi)
			hi = hi['result']
			htlce.append(hi)
			pprint(hi)
		except asyncio.TimeoutError:
			print('timeout!')
		except asyncio.CancelledError:
			print("cancelled?")


async def blockstream():
	ws = await websockets.connect("wss://10.0.0.111:8080/v2/chainnotifier/register/blocks?method=POST", ping_timeout=None, ping_interval=20, ssl=ssl_context, extra_headers=headers, max_size=1000000000)
	print('waiting')
	await asyncio.sleep(1)
	print('priming')
	await ws.send(json.dumps({'height':641549,'hash':base64.b64encode(b'000000000000000000100a0cdd08a73ebf397c0f0d261d7877c3c55b4bfb4e94').decode()}).encode('UTF-8'))
	async for message in ws:
		print('receiving')
		try:
			hi = await asyncio.wait_for(ws.recv(), timeout=60)
			hi = json.loads(hi)
			hi = hi['result']
			await ws.ping()
			pprint(hi)
		except asyncio.TimeoutError:
			print('timeout!')
		except asyncio.CancelledError:
			print("cancelled?")

async def main():
	loop = asyncio.get_event_loop()
	await htlcevents2()
	# await lc()
	# await blockstream()

import threading

def async_layer():
	asyncio.run(main())

# async thread
x = threading.Thread(target=async_layer, daemon=True)
x.start()

async def fetch(client):
	print('fetch')
	async with client.get("wss://10.0.0.111:8080/v2/router/htlcevents?method=GET",ssl=ssl_context) as resp:
		print('get!')
		return await resp.text()

async def main():
	async with aiohttp.ClientSession(headers=headers) as client:
		print('starting')
		html = await fetch(client)
		print(html)

loop = asyncio.get_event_loop()
loop.run_until_complete(main())



# Get channels and fees
z = listGetChannelFees()
# Get low fee destinations with low balance
y = z.query("fee_rate_milli_msat <= 10 and active == True").sort_values(["balanced"],ascending=[1])


oid = '694266826229022721'
lh = '022b213281fad5065c66ed53a53198a04b4cb528ce92d76ed0175471b93f1db74f'
a,b,c,d = rebalance(100000,oid,lh,4500,force=True)

def multibalance(d):
	global oid
	global lh
	hops = list(d.pub_key)
	for i,row in openInvoices().query("memo == 'balance'").sort_values("value_msat")[::-1].iterrows():
		try:
			rhash = row["r_hash"]
			balance_amt = int(row["value_msat"]/1000)
			print(f"Balancing: {balance_amt}")
			r = buildRoute(hops,balance_amt)
			pprint(sendRoute(rhash,r))
			listChannels().query('chan_id.str.contains(@oid) or remote_pubkey.str.contains(@lh)')
		except Exception as e:
			print(e)

def resetInvoices():
	# Reset buffer of invoices
	oinv = openInvoices()
	need = set({100000,200000,300000,400000,500000}) - set((oinv.query("memo == 'balance'").sort_values("value_msat").value_msat/1000).astype(int))
	for val in need:
		print(f"Adding Amount: {val}")
		addInvoice(val,'balance')


t = rebalancePartners()
b = pandas.DataFrame(t)
b.columns = ["one","two","three"]
b.query("one == '02875ac2c27835990ef62e5755c34264b2c39f51a41525adc5e52a7f94b3a19f8b'").two.apply(lambda x: getAlias(x))
hops  = list(b.iloc[1429])
r = buildRoute(hops,100000)
invoice = addInvoice(100000,'test')
pprint(sendRoute(invoice['r_hash'],r))


avail_routes = b.query("one == '02875ac2c27835990ef62e5755c34264b2c39f51a41525adc5e52a7f94b3a19f8b'").two.apply(lambda x: getAlias(x))
avail_index = avail_routes.index



# Get channels and fees
z = listGetChannelFees()
# Get low fee destinations with low balance
y = z.query("fee_rate_milli_msat <= 10 and active == True").sort_values(["balanced"],ascending=[1])

low_fee_fh_pk = list(y[60:73].remote_pubkey)
low_fee_lh_pk = list(y[0:12].remote_pubkey)

avail_routes = b.query("one.isin(@low_fee_fh_pk) and two.isin(@low_fee_lh_pk)")
avail_index = avail_routes.index




invoice = addInvoice(200000,'test')
fee_sum = 0
for h in avail_index:
	hops  = list(b.iloc[h])
	try:
		r = buildRoute(hops,200000)
		if int(r['total_fees_msat'])/1000 > 4:
			print("FEE TOO HIGH!")
			continue
	except Exception as e:
		print(f"build route error: {hops} {h}")
		continue
	pay = sendRoute(invoice['r_hash'],r)
	# pprint(pay)
	if 'error' in pay:
		pprint(pay)
	if pay['status'] == 'SUCCEEDED':
		invoice = addInvoice(200000,'test')
		print("Success!\n")
		fees = float(pay['route']['total_fees_msat'])/1000
		print(fees)
		fee_sum += fees
		print(listChannels().query("remote_pubkey.isin(@hops)"))
		for i in hops:
			getAlias(i)
	
	# cont = input('continue?')
	# if not cont.startswith('y'):
	# 	break
		

# Check Result
listChannels().query("chan_id == '683535592764866560'")

if __name__ == "__main__":
	code.interact(local=locals())