import requests
import base64, codecs, json, requests
import binascii
import io
import code
from rich import print

from pprint import pprint, pformat
import pandas
from pandas import Series
from math import floor, fsum
from datetime import datetime, timedelta
from hashlib import sha256

pandas.set_option("display.max_colwidth", None)
pandas.set_option("display.max_rows", None)
pandas.options.display.float_format = "{:.5f}".format

import logging
import traceback
import os
import urllib.parse
import hashlib

import tempfile

# SRC IMPORTS
from lnd_pyshell.base_requests import *

from lnd_pyshell.network import *


# polar = False
# # polar = True
# polar_port = 1
# polar_name = "alice"
# polar_name = 'erin'
# polar_name = 'dave'


# LND_DIR = f'{os.getenv("HOME")}/.lnd'

# # LND_DIR = f'{os.getenv("HOME")}/.polar/networks/1/volumes/lnd/{polar_name}'
# print(LND_DIR)

# # Select mainnet or testnet
# CHAIN = "mainnet"
# # CHAIN = 'regtest'
# # CHAIN = 'testnet'

# macaroon_path = f"{LND_DIR}/data/chain/bitcoin/{CHAIN}/admin.macaroon"
# if os.path.exists(macaroon_path):
#     macaroon = codecs.encode(open(macaroon_path, "rb").read(), "hex")
# else:
#     macaroon = os.getenv("MAC")

# cert_path = LND_DIR + "/tls.cert"
# if not os.path.exists(cert_path):
#     tls = os.getenv("TLS")
#     a = bytes.fromhex(tls)
#     fp = tempfile.NamedTemporaryFile()
#     fn = fp.name
#     fp.write(a)
#     fp.seek(0)
#     cert_path = fn


# headers = {"Grpc-Metadata-macaroon": macaroon}


# port = 8080

# if polar:
#     port = port + polar_port

# # MAIN IP
# base_url = f'https://{os.getenv("NODE_IP")}:{port}'

# Polar IP 1
# base_url = f'https://{os.getenv("NODE_IP")}:8081'
# Polar IP 2
# base_url = f'https://{os.getenv("NODE_IP")}:8082'
# Polar IP 3
# base_url = f'https://{os.getenv("NODE_IP")}:8082'
# Polar IP 2
# base_url = f'https://{os.getenv("NODE_IP")}:8082'
print(base_url)

# THIS HOLDS A CACHE OF PUB-KEY to ALIAS CONVERSIONS
pkdb = {}

# ERROR List
# {'error': 'permission denied', 'message': 'permission denied', 'code': 2}

##### Base GET/POST  REQUEST
# def sendPostRequest(endpoint, data={}, debug=False):
#     url = base_url + endpoint
#     r = requests.post(url, headers=headers, verify=cert_path, data=json.dumps(data))
#     try:
#         return r.json()
#     except ValueError as e:
#         print(f"Error decoding JSON: {e}")
#         print(r)
#         return r


# def sendGetRequest(endpoint, ext="", body=None, debug=False):
#     url = base_url + endpoint.format(ext)
#     if debug:
#         print(f"GET: {url}")
#     r = requests.get(url, headers=headers, verify=cert_path, data=body)
#     try:
#         return r.json()
#     except ValueError as e:
#         print(f"Error decoding JSON: {e}")
#         print(r)
#         return r


# def sendDeleteRequest(endpoint, data="", debug=False):
#     url = base_url + endpoint
#     if debug:
#         print(f"DELETE: {url}")
#     r = requests.delete(url, headers=headers, verify=cert_path, data=json.dumps(data))
#     try:
#         return r.json()
#     except ValueError as e:
#         print(f"Error decoding JSON: {e}")
#         print(r)
#         return r


##### WALLET UNLOCK!




# ****** CHANNEL ******
def getChannelDisabled(cid, mypk=None):
    # Build in optimization if PK is handy
    cframe = getChanPolicy(cid)
    if mypk == None:
        mypk = getMyPk()
    print(mypk)
    d = cframe[cframe["pubkey"] != mypk]
    # Get only remaining item left
    print(d)
    index = list(set(d.index))[0]
    print(index)
    cstate = d.loc[int(index), "disabled"]
    return cstate






# System Functions






def getNodeChannels(pubkey):
    nodedata = getNodeInfo(pubkey, channels=True)
    channels = nodedata["channels"]
    partners = []
    for c in channels:
        if c["node1_pub"] != pubkey:
            c["node1_policy"].update({"pubkey": c["node1_pub"]})
            policy = c["node1_policy"]
            partners.append(policy)
        else:
            c["node2_policy"].update({"pubkey": c["node2_pub"]})
            policy = c["node2_policy"]
            partners.append(policy)
    nodepartners = pandas.DataFrame(partners)
    nodepartners["alias"] = nodepartners.pubkey.apply(lambda x: getAlias(x))
    return nodepartners


def getNodeChannels2(pubkey):
    nodedata = getNodeInfo(pubkey, channels=True)
    # channel_frame = pandas.DataFrame(nodedata['channels'])
    chan = []
    print(f"Number of channels: {len(nodedata['channels'])}")
    for achan in nodedata["channels"]:
        try:
            # (achan)
            if achan["node1_pub"] == None or achan["node2_pub"] == None:
                chan.append({})
            elif achan["node1_pub"] != pubkey:
                chan.append(
                    {
                        "chan_id": achan["channel_id"],
                        "pubkey": achan["node1_pub"],
                        **achan["node1_policy"],
                        "capacity": achan["capacity"],
                    }
                )
            else:
                chan.append(
                    {
                        "chan_id": achan["channel_id"],
                        "pubkey": achan["node2_pub"],
                        **achan["node2_policy"],
                        "capacity": achan["capacity"],
                    }
                )
        except Exception as e:
            print(e)

    a = pandas.DataFrame(chan)
    a["alias"] = a.pubkey.apply(lambda x: getAlias(x))
    return a














def main():
    from lnd_pyshell.base_requests import sendGetRequest, sendPostRequest
    from lnd_pyshell.channels import listChannels
    print(f"Welcome to the LN: [bold cyan]{getMyAlias()}[/bold cyan].")
    print(listChannels())
    print("[green]****[/green] [yellow]MUST IMPORT[/yellow] [green]****[/green] ...")
    print("[bold yellow]from lnd_pyshell.lnd_rest import *[/bold yellow]")
    print("[bold yellow]from lnd_pyshell.utils import *[/bold yellow]")
    print("[bold yellow]from lnd_pyshell.rebalance import *[/bold yellow]")
    print("[bold yellow]from lnd_pyshell.invoices import *[/bold yellow]")
    print("[bold yellow]from lnd_pyshell.channels import *[/bold yellow]")
    print("[bold yellow]from lnd_pyshell.onchain import *[/bold yellow]")
    print("[bold yellow]from lnd_pyshell.fees import *[/bold yellow]")
    print("[bold yellow]from lnd_pyshell.network import *[/bold yellow]")
    print("[bold yellow]from lnd_pyshell.routing import *[/bold yellow]")
    print("[bold yellow]from time import sleep[/bold yellow]")
    code.interact(local=locals())


if __name__ == "__main__":
    main()
