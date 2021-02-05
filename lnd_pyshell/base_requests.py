import os
import requests
import json
import tempfile
import codecs

# Loop support?
LND = False
LOOP = True

LND = True
LOOP = False

LND_DIR = f'{os.getenv("HOME")}/.lnd'
LOOP_DIR = f'{os.getenv("HOME")}/.loop'


# LND_DIR = f'{os.getenv("HOME")}/.polar/networks/1/volumes/lnd/{polar_name}'
print(LND_DIR)

# Select mainnet or testnet
CHAIN = "mainnet"
# CHAIN = 'regtest'
# CHAIN = 'testnet'

macaroon_path = f"{LND_DIR}/data/chain/bitcoin/{CHAIN}/admin.macaroon"
if os.path.exists(macaroon_path):
    macaroon = codecs.encode(open(macaroon_path, "rb").read(), "hex")
else:
    macaroon = os.getenv("MAC")

cert_path = LND_DIR + "/tls.cert"
if not os.path.exists(cert_path):
    tls = os.getenv("TLS")
    a = bytes.fromhex(tls)
    fp = tempfile.NamedTemporaryFile()
    fn = fp.name
    fp.write(a)
    fp.seek(0)
    cert_path = fn


headers = {"Grpc-Metadata-macaroon": macaroon}


port = 8080

# MAIN IP
base_url = f'https://{os.getenv("NODE_IP")}:{port}'


def sendPostRequest(endpoint, data={}, debug=False):
    url = base_url + endpoint
    # r = requests.post(url, headers=headers, verify=cert_path, data=json.dumps(data))
    r = requests.post(url, headers=headers, data=json.dumps(data))
    try:
        return r.json()
    except ValueError as e:
        print(f"Error decoding JSON: {e}")
        print(r)
        return r


def sendGetRequest(endpoint, ext="", body=None, debug=False):
    url = base_url + endpoint.format(ext)
    if debug:
        print(f"GET: {url}")
    # r = requests.get(url, headers=headers, verify=cert_path, data=body)
    # r = requests.get(url, headers=headers, data=body)
    # r = requests.get(url, headers=headers, verify=cert_path, data=body)
    r = requests.get(url, headers=headers, verify=None, data=body)
    try:
        return r.json()
    except ValueError as e:
        print(f"Error decoding JSON: {e}")
        print(r)
        return r


def sendDeleteRequest(endpoint, data="", debug=False):
    url = base_url + endpoint
    if debug:
        print(f"DELETE: {url}")
    # r = requests.delete(url, headers=headers, verify=cert_path, data=json.dumps(data))
    r = requests.delete(url, headers=headers, data=json.dumps(data))
    try:
        return r.json()
    except ValueError as e:
        print(f"Error decoding JSON: {e}")
        print(r)
        return r
