# WEBSOCKETS!
import websockets
import asyncio
import ssl
import logging
logger = logging.getLogger('websockets')
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_verify_locations(cert_path)

htlce = []
async def htlcevents2():
	ws = await websockets.connect("wss://192.168.1.12:8080/v2/router/htlcevents?method=GET", ping_timeout=None, ping_interval=20, ssl=ssl_context, extra_headers=headers, max_size=1000000000)
	print('waiting')
	await asyncio.sleep(1)
	print('priming')
	await ws.send(json.dumps({}).encode('UTF-8'))

	message = await asyncio.wait_for(ws.recv(), timeout=5)
	while message:
		print('receiving')
		try:
			hi = json.loads(hi)
			if hi.get('result'):
				hi = hi['result']
				htlce.append(hi)
				pprint(hi)
			hi = await asyncio.wait_for(ws.recv(), timeout=5)
		except asyncio.TimeoutError:
			print('timeout!')
		except asyncio.CancelledError:
			print("cancelled?")

page = await fetch_page()
while page:
	for doc in page:
		yield doc
	page = await fetch_page()


async def closeChannelStream():
	channel_point = "8eaeed4da5d1e42b480792a43e5078172bf3f361d2970fe7db6f2bd8fe6d1850"
	output_index = 1
	force = False
	fee_rate = 3
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


async def main():
	loop = asyncio.get_event_loop()
	# await closeChannelStream()
	await htlcevents2()
	# await lc()
	# await blockstream()


loop = asyncio.get_event_loop()
loop.run_until_complete(main())