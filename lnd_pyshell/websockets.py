# WEBSOCKETS!
import websockets
import asyncio
import ssl
import logging
import os
logger = logging.getLogger('websockets')
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_verify_locations(cert_path)

os.environ['PYTHONASYNCIODEBUG'] = True


def viewhtlcs():
	htlce = []
	async def htlcevents2():
		ws = await websockets.connect("wss://192.168.1.12:8080/v2/router/htlcevents?method=GET", ping_timeout=None, ping_interval=20, ssl=ssl_context, extra_headers=headers, max_size=1000000000)
		print('waiting')
		await asyncio.sleep(1)
		print('priming')
		await ws.send(json.dumps({}).encode('UTF-8'))
		# message = await asyncio.wait_for(ws.recv(), timeout=5)
		hi = '{"test":1}'
		while hi:
			print('receiving')
			try:
				hi = json.loads(hi)
				if hi.get('result'):
					hi = hi['result']
					print(f"Available Keys: {hi.keys()}")
					htlce.append(hi)
					# Channel Info
					in_id = hi['incoming_channel_id']
					out_id = hi['outgoing_channel_id']
					print(listChannels().query(f'chan_id.isin({[in_id,out_id]})'))
					print(f'Source: {out_id} --> {CID2Alias(out_id)}')
					print(f'Dest: {in_id} --> {CID2Alias(in_id)}')
					# Event Info
					print(f"Event Type: {hi['event_type']}")
					print(hi['link_fail_event']['failure_string'])
					fwd_amt = float(hi['link_fail_event']['info']['outgoing_amt_msat'])/1000
					print(f"Forwarding Amount: {fwd_amt}")
					# FEE INFO
					in_msat = int(hi['link_fail_event']['info']['incoming_amt_msat'])
					out_msat = int(hi['link_fail_event']['info']['outgoing_amt_msat'])
					fee_sat = (in_msat-out_msat)/1000
					print(f"Fees: {fee_sat} sats")
					fee_rate = fee_sat / fwd_amt
					print(f"Fee Rate: {fee_rate:0.6f}")
				hi = await asyncio.wait_for(ws.recv(), timeout=5)
			except asyncio.TimeoutError:
				print('timeout!')
				hi = '{"test":1}'
			except asyncio.CancelledError:
				print("cancelled?")
			except KeyError as e:
				print(f"KeyError: {e}")
				hi = '{"test":1}'
			except KeyboardInterrupt:
				break
	asyncio.run(htlcevents2())


	loop = asyncio.get_event_loop()
	loop.run_until_complete(htlcevents2())
	a = pandas.DataFrame(htlce)
	print("Done!")
	print(a)
	return a
	

def sendPaymentV2():
	async def sendPaymentWS2():
		url = f'wss://192.168.1.12:8080/v2/router/send?method=POST'
		ws = await websockets.connect(url, ping_timeout=None, ping_interval=30, ssl=ssl_context, extra_headers=headers, max_size=1000000000)
		data = { 
			'payment_request': pr, 
			'timeout_seconds': 120, 
			'fee_limit_sat': 100, 
			'allow_self_payment': True, 
			'max_parts': 4, 
			'no_inflight_updates': False, 
		}
		close_data = {}
		await ws.send(json.dumps(data).encode('UTF-8'))
		print("Reading data")
		hi = await asyncio.wait_for(ws.recv(), timeout=15)
		print(hi)
		count = 0
		while hi:
			try:
				hi = json.loads(hi)
				pprint(hi['result'])
				print(f"Count: {count}")
				if hi.get('htlcs'):
					print(f"HTLCs: {len(hi['htlcs'])}")
				count += 1
				hi = await asyncio.wait_for(ws.recv(), timeout=15)
			except websockets.ConnectionClosed:
				print("Connection terminated.")
				break
	loop = asyncio.get_event_loop()
	loop.run_until_complete(sendPaymentWS2())


async def listPayments():
	url = f'wss://192.168.1.12:8080/v1/payments?method=GET'
	ws = await websockets.connect(url, ping_timeout=None, ping_interval=30, ssl=ssl_context, extra_headers=headers, max_size=1000000000)
	close_data = {}
	await ws.send(json.dumps({}).encode('UTF-8'))
	print("Reading data")
	hi = await asyncio.wait_for(ws.recv(), timeout=5)
	print(hi)
	while hi:
		print(hi)
		hi = await asyncio.wait_for(ws.recv(), timeout=5)

# '95f0d52d8426aa86c5b37609f0cf78c095549101d32763bb1f2957b615a21def:1'
def closeChannelSync(cid):
	cp = CID2CP(cid)
	print(f"Closing Channel with Alias: {CID2Alias(cid)} CID: {cid}")
	async def closeChannelStream(cp):
		channel_point, output_index = cp.split(':')
		# channel_point = "8eaeed4da5d1e42b480792a43e5078172bf3f361d2970fe7db6f2bd8fe6d1850"
		# output_index = 1
		force = False
		fee_rate = 1
		url = f'/v1/channels/{channel_point}/{output_index}?force={force}&sat_per_byte={fee_rate}'
		ws = await websockets.connect(f"wss://192.168.1.12:8080{url}&method=DELETE", ping_timeout=None, ping_interval=30, ssl=ssl_context, extra_headers=headers, max_size=1000000000)
		close_data = {}
		await ws.send(json.dumps({}).encode('UTF-8'))
		hi = await ws.recv()
		print(hi)
		count = 0
		while True:
			print('receiving')
			try:
				hi = json.loads(hi)
				print(hi)
				if hi.get('result'):
					print('breaking out of loop!')
					txid_b64 = hi['result']['close_pending']['txid']
					outindex = hi['result']['close_pending']['output_index']
					txid = binascii.hexlify(base64.b64decode(txid_b64)[::-1])
					print(f"TXID: {txid}\tOutput Index: {outindex}")
					break
				hi = await asyncio.wait_for(ws.recv(), timeout=5)
				count += 1
				if count > 10:
					break
			except asyncio.TimeoutError:
				print('timeout!')
			except asyncio.CancelledError:
				print("cancelled?")
	loop = asyncio.get_event_loop()
	loop.run_until_complete(closeChannelStream(cp))


async def SubscribeChannelEvents():
	url = '/v1/channels/subscribe'
	ws = await websockets.connect(f"wss://192.168.1.12:8080{url}?method=GET", ping_timeout=None, ping_interval=30, ssl=ssl_context, extra_headers=headers, max_size=1000000000)
	close_data = {}
	await ws.send(json.dumps({}).encode('UTF-8'))
	hi = await ws.recv()
	while True:
		print(hi)
		count = 0
		hi = await ws.recv()


def sg():
	async def SubscribeGraphStream():
		url = ' /v1/graph/subscribe'
		ws = await websockets.connect(f"wss://192.168.1.12:8080{url}?method=GET", ping_timeout=None, ping_interval=30, ssl=ssl_context, extra_headers=headers, max_size=1000000000)
		close_data = {}
		await ws.send(json.dumps({}).encode('UTF-8'))
		hi = await ws.recv()
		while True:
			try:
				hi = json.loads(hi)
				pprint(hi)
				count = 0
				hi = await ws.recv()
			except asyncio.TimeoutError:
				print('[bold red]timeout![/bold red]')
			except asyncio.CancelledError:
				print("[bold red]cancelled?[/bold red]")
			except KeyboardInterrupt:
				print("[bold red]Breaking out of loop[/bold red]")
				break
	loop = asyncio.get_event_loop()
	loop.run_until_complete(SubscribeGraphStream())


async def SubscribeInvoices():
	url = ' /v1/invoices/subscribe?add_index=5000'
	ws = await websockets.connect(f"wss://192.168.1.12:8080{url}&method=GET", ping_timeout=None, ping_interval=30, ssl=ssl_context, extra_headers=headers, max_size=1000000000)
	close_data = {}
	await ws.send(json.dumps({}).encode('UTF-8'))
	hi = await ws.recv()
	while True:
		print(hi)
		count = 0
		hi = await ws.recv()


async def SubscribePeers():
	url = ' /v1/peers/subscribe'
	ws = await websockets.connect(f"wss://192.168.1.12:8080{url}?method=GET", ping_timeout=None, ping_interval=30, ssl=ssl_context, extra_headers=headers, max_size=1000000000)
	close_data = {}
	await ws.send(json.dumps({}).encode('UTF-8'))
	hi = await ws.recv()
	while True:
		print(hi)
		count = 0
		hi = await ws.recv()


def openChannel(ln_at_url,sats,fee=1,suc=False):
	url = '/v1/channels'
	# apk = f'{pk}'.encode('UTF-8')
	print(connectPeer(ln_at_url))
	pubkey,host = ln_at_url.split('@')
	node_pubkey = base64.b64encode(bytes.fromhex(pubkey)).decode()
	# 'node_pubkey_string': f'{pk}',
	data = {
		# 'node_pubkey_string': f'{pubkey}',
		# This doesnt work but theoretically this is the better way
		'node_pubkey': node_pubkey,
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


async def main():
	loop = asyncio.get_event_loop()
	# await closeChannelStream(cps[3])
	# await SubscribeGraph()
	await SubscribePeers()
	# await SubscribeChannelEvents()


loop = asyncio.get_event_loop()
loop.run_until_complete(main())