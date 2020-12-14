import requests
import base64, codecs, json, requests
import binascii
import io
import code
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
from rich import print
import tempfile

# SRC IMPORTS
from lnd_pyshell.base_requests import *


polar = False
# polar = True
polar_port = 1
polar_name = "alice"
# polar_name = 'erin'
# polar_name = 'dave'


LND_DIR = f'{os.getenv("HOME")}/.lnd'

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

if polar:
    port = port + polar_port

# MAIN IP
base_url = f'https://{os.getenv("NODE_IP")}:{port}'

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
def sendPostRequest(endpoint, data={}, debug=False):
    url = base_url + endpoint
    r = requests.post(url, headers=headers, verify=cert_path, data=json.dumps(data))
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
    r = requests.get(url, headers=headers, verify=cert_path, data=body)
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
    r = requests.delete(url, headers=headers, verify=cert_path, data=json.dumps(data))
    try:
        return r.json()
    except ValueError as e:
        print(f"Error decoding JSON: {e}")
        print(r)
        return r


##### WALLET UNLOCK!
def unlockWallet():
    password = base64.b64encode(os.getenv("PASS").encode("UTF-8")).decode()
    sendPostRequest(
        "/v1/unlockwallet",
        {
            "wallet_password": password,
            # 'recovery_window': 0,
            # channel_backups: None
        },
    )


def getMyAlias():
    myalias = getAlias(getMyPK())
    return myalias


##### Route
# listChannels().query('alias == "yalls.org"')
# hops = pandas.DataFrame(buildRoute()['route']['hops'])
# hops['alias'] = hops.apply(lambda x: getAlias(x.pub_key), axis=1)
def buildRoute(hops, amt=1, cltv_delta=40):
    url = "/v2/router/route"
    data = {}
    hops_base64 = [base64.b64encode(bytes.fromhex(apk)).decode() for apk in hops]
    data["hop_pubkeys"] = hops_base64
    # data['outgoing_chan_id'] = '688959483615510529'
    data["amt_msat"] = amt * 1000
    data["final_cltv_delta"] = cltv_delta
    lnreq = sendPostRequest(url, data)
    return lnreq["route"]


# paymentHash: sha("sha256").update(preImage).digest(),
# invoice = addInvoice(10000,'testcustomroute')

# sendRoute()


def sendRoute(r_hash, route):
    # Send directly to route
    url = "/v2/router/route/send"
    data = {}
    h = hashlib.sha256()
    h.update(base64.b64decode(r_hash))
    # data['payment_hash'] = base64.b64encode(h.digest()).decode()
    data["payment_hash"] = r_hash
    data["route"] = route
    lnreq = sendPostRequest(url, data)
    return lnreq


def createWallet():
    url = "/v1/initwallet"
    data["wallet_password"] = None
    data["cipher_seed_mnemonic"] = None
    data["aezeed_passphrase"] = None


##### Payment Functions
def sendPaymentByReq(payreq, oid=None, lasthop=None, allow_self=False):
    # TODO: Add ability for this to return true/false success of payment
    url = "/v1/channels/transactions"
    data = {}
    data["payment_request"] = payreq
    if oid:
        data["outgoing_chan_id"] = oid
    if lasthop:
        data["last_hop_pubkey"] = base64.b64encode(bytes.fromhex(lasthop)).decode()
    if allow_self:
        data["allow_self_payment"] = True
    # if outid != None:
    # 	data = {'payment_request': payreq, 'outgoing_chan_id': outid}
    # data = {'payment_request': payreq, 'payment_hash_string':'2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'}
    lnreq = sendPostRequest(url, data)
    pprint(lnreq)
    try:
        pay_frame = pandas.DataFrame(lnreq["payment_route"]["hops"])
        pay_frame
        pay_frame["alias"] = pay_frame.apply(lambda x: getAlias(x.pub_key), axis=1)
        pay_frame
        return pay_frame
    except KeyError as e:
        print(f"Error: payment_error {lnreq['payment_error']}")
        return lnreq


def sendPaymentV2(
    payreq, oid=None, lasthop=None, allow_self=False, fee_msat=3000, parts=1
):
    url = "/v2/router/send"
    data = {}
    data["outgoing_chan_id"] = f"{oid}"
    data["payment_request"] = payreq
    if lasthop:
        data["last_hop_pubkey"] = base64.b64encode(bytes.fromhex(lasthop)).decode()
    if allow_self:
        data["allow_self_payment"] = True

    data["fee_limit_msat"] = fee_msat
    data["max_parts"] = parts
    data["timeout_seconds"] = 180
    try:
        lnreq = sendPostRequest(url, data)
        lnreq = json.loads(lnreq.text.split("\n")[len(lnreq.text.split("\n")) - 2])
        num_htlcs = len(lnreq["result"]["htlcs"])
        print(f"Number of attempted htlcs to complete transaction: {num_htlcs}")
        htlc_frame = []
        for htlc in lnreq["result"]["htlcs"]:
            successful_htlcs = 0
            if htlc["failure"] == None:
                successful_htlcs += 1
                pay_frame = pandas.DataFrame(htlc["route"]["hops"])
                pay_frame["alias"] = pay_frame.apply(
                    lambda x: getAlias(x.pub_key), axis=1
                )
                pay_frame.columns
                pay_frame = pay_frame[
                    [
                        "alias",
                        "chan_id",
                        "pub_key",
                        "amt_to_forward",
                        "fee",
                        "fee_msat",
                        "tlv_payload",
                    ]
                ]
                # pay_frame
                htlc_frame.append(pay_frame)

        print(f"Routing using {successful_htlcs} successful HTLCs!")
        return htlc_frame, lnreq
    except KeyError as e:
        print(f"Error: payment_error {lnreq['payment_error']}")
        return lnreq


def htlcevents():
    r = requests.get(url, headers=headers, verify=cert_path, stream=True)
    for raw_response in r.iter_lines():
        json_response = json.loads(raw_response)
        print(json_response)


def PayByRoute(route, pay_hash=None):
    url = "/v1/channels/transactions/route"
    if pay_hash == None:
        pay_hash = base64.b64encode(b"blah1234").decode()
    else:
        pay_hash = base64.b64encode(pay_hash.encode("UTF-8")).decode()
    data = {
        "payment_hash": pay_hash,
        "route": route,
    }
    lnreq = sendPostRequest(url, data)
    pprint(lnreq)
    return lnreq


def generateSeed():
    password = base64.b64encode(b"testing1234").decode()
    entropy = base64.b64encode(b"").decode()
    url = f"/v1/genseed?seed_entropy={entropy}&aezeed_passphrase={password}"
    url = f"/v1/genseed"
    data["seed_entropy"] = entropy
    data["aezeed_passphrase"] = password
    print(url)
    lnreq = sendPostRequest(url, data)


def getNewAddress(old=False):
    url = f"/v1/newaddress?type={1 if old else 0}"
    lnreq = sendGetRequest(url)
    return lnreq["address"]


def getChanPoint(chanid):
    lnreq = getEdgeInfo(chanid)
    cp = lnreq["chan_point"]
    return cp


def listPendingChannels():
    url = "/v1/channels/pending"
    lnreq = sendGetRequest(url)
    pending_types = list(set(lnreq.keys()) - {"total_limbo_balance"})
    pending_types
    # print(lnreq)
    b = []
    for a in lnreq["pending_open_channels"]:
        a.update(**a["channel"])
        del a["channel"]
        b.append(a)
    c = pandas.DataFrame(b)
    c["alias"] = c.remote_node_pub.apply(lambda x: getAlias(x))
    return c


# ****** GRAPH ******
def describeGraph():
    url = "/v1/graph"
    lnreq = sendGetRequest(url)
    return lnreq


def exportGraphToCSV(filename="graph.json"):
    graph = describeGraph()
    nodes = len(graph["nodes"])
    edges = len(graph["edges"])
    print(f"Found { nodes } nodes and { edges } edges in the graph")
    b = None
    with open(filename, "w") as f:
        b = f.write(json.dumps(graph))
        print(b)
        print(f"Wrote {b/1024/1204}MB of graph data to: {filename}")


def nodeMetrics():
    # doesnt work
    url = "/v1/graph/nodemetrics?types=1"
    lnreq = sendGetRequest(url)
    frame = pandas.DataFrame.from_dict(lnreq["betweenness_centrality"]).T
    frame.reset_index(inplace=True)
    frame.rename(columns={"index": "pubkey"}, inplace=True)
    frame.sort_values(by="normalized_value", inplace=True)
    return frame


def channelMetrics():
    chans = list(listChannels().remote_pubkey)
    a = nodeMetrics()
    b = a.query("pubkey.isin(@chans)")
    # b.sort_values(by="normalized_value",inplace=True)
    return b


def getMyEdges():
    graph = describeGraph()
    edges = graph["edges"]
    eframe = pandas.DataFrame(edges)
    mpk = getMyPk()
    myedges = eframe.query(
        f'node1_pub.str.contains("{mpk}") | node2_pub.str.contains("{mpk}")'
    )
    return myedges


# ****** FEE INFO ******
def updateChanPolicy(
    chan_point=None, fee_rate=0.000001, base_fee_msat=300, tld=40, min_htlc=None
):
    url = "/v1/chanpolicy"
    data = {
        "time_lock_delta": tld,
        "min_htlc_msat_specified": False,
        "fee_rate": fee_rate,
        "base_fee_msat": str(base_fee_msat),
        "max_htlc_msat": str(2000000000),
    }
    if min_htlc != None:
        data.update({"min_htlc_msat": min_htlc, "min_htlc_msat_specified": True})
    if chan_point == None:
        data.update({"global": True})
    else:
        cp, out_index = chan_point.split(":")
        pc = bytearray.fromhex(cp)
        pc.reverse()
        pc = binascii.hexlify(pc).decode()
        data.update(
            {
                "chan_point": {
                    "funding_txid_bytes": base64.b64encode(bytes.fromhex(pc)).decode(),
                    "output_index": out_index,
                }
            }
        )
    print(f"Using Data: {data}")
    lnreq = sendPostRequest(url, data)
    print(lnreq)
    return lnreq


def feeReport():
    url = "/v1/fees"
    lnreq = sendGetRequest(url)
    fee_frame = pandas.DataFrame(lnreq["channel_fees"])
    fee_frame["alias"] = fee_frame.chan_id.apply(lambda x: CID2Alias(x))
    return fee_frame


# ****** CHANNEL ******
def getEdgeInfo(chanid):
    url = f"/v1/graph/edge/{chanid}"
    lnreq = sendGetRequest(url)
    return lnreq


def getChanPolicy(chanid, pubkey=None, npk=None):
    lnreq = getEdgeInfo(chanid)
    try:
        df = pandas.DataFrame.from_dict(
            {
                lnreq["node1_pub"]: lnreq["node1_policy"],
                lnreq["node2_pub"]: lnreq["node2_policy"],
            }
        )
        df = df.T
        df.reset_index(inplace=True)
        df.rename(columns={"index": "pubkey"}, inplace=True)
        df["alias"] = df["pubkey"].apply(lambda x: getAlias(x))
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
    except KeyError as e:
        print(e)
        return None


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


def getBalance(row):
    return row["local_balance"] / (row["local_balance"] + row["remote_balance"])


def getChanSize(row):
    return row["local_balance"] + row["remote_balance"]


def getToBalance(row, target=500000):
    return target - row["local_balance"]


def listGetChannelFees():
    # Get fee info to route through channel
    data = []
    c = listChannels()
    c = c.sort_index()
    for i in c.chan_id:
        try:
            chan_policy = (
                getChanPolicy(i)
                .query(f"pubkey != '{ getMyPK() }'")[
                    ["pubkey", "min_htlc", "fee_base_msat", "fee_rate_milli_msat"]
                ]
                .to_dict("records")[0]
            )
            chan_policy["chan_id"] = i
            data.append(chan_policy)
        except KeyError as e:
            print(f"Error for chan id: {i} --> {e}")
    t = pandas.DataFrame(data)
    c["fee_base_msat"] = t["fee_base_msat"].astype(int)
    c["fee_rate_milli_msat"] = t["fee_rate_milli_msat"].astype(int)
    channels_with_fees = c[
        [
            "active",
            "alias",
            "chan_id",
            "remote_pubkey",
            "fee_rate_milli_msat",
            "fee_base_msat",
            "balanced",
            "local_balance",
        ]
    ]
    channels_with_fees = channels_with_fees.sort_values(
        ["fee_rate_milli_msat", "local_balance"], ascending=[1, 1]
    )
    # t.query("fee_rate_milli_msat < 6").sort_values(['balanced','fee_rate_milli_msat'],ascending=[1,1])
    return channels_with_fees


# z = listGetChannelFees()
# z.query("fee_rate_milli_msat <= 10").sort_values(["balanced"],ascending=[1])


def listChannels(chanpoint=None, all=False, disabled=False, private=False):
    url = "/v1/channels"
    if private:
        url += "?private_only=true"
    lnreq = sendGetRequest(url)
    # Check if no channels
    if not lnreq["channels"]:
        return lnreq
    # print(lnreq)
    d = pandas.DataFrame(lnreq["channels"])
    y = d[
        [
            "active",
            "chan_id",
            "channel_point",
            "remote_pubkey",
            "local_balance",
            "remote_balance",
            "capacity",
        ]
    ].fillna(0)
    # Convert columns to integers
    y[["local_balance", "remote_balance", "capacity"]] = y[
        ["local_balance", "remote_balance", "capacity"]
    ].apply(pandas.to_numeric, errors="coerce")
    y["balanced"] = y.apply(getBalance, axis=1)
    y["alias"] = y.apply(lambda x: getAlias(x.remote_pubkey), axis=1)
    y["tobalance"] = y.apply(getToBalance, axis=1)
    # y = y.sort_values(by=['balanced'])
    y = y.sort_values(by=["local_balance"], ascending=False)
    # y = y.sort_values(by=['balanced'])
    # Get balance ratio of all channels
    rb = y["remote_balance"].sum()
    lb = y["local_balance"].sum()
    print(f"Local to remote balance ratio: {lb/(lb+rb)}")
    # y = y.set_index("channel_point")
    if disabled:
        pk = getMyPk()
        y["d_cp"] = y.apply(lambda x: getChannelDisabled(x, pk), axis=1)
    if chanpoint:
        y = y[y.index == chanpoint]
    if all:
        return y
    else:
        return y[
            [
                "active",
                "alias",
                "balanced",
                "capacity",
                "local_balance",
                "remote_balance",
                "chan_id",
                "remote_pubkey",
            ]
        ]


def connectPeer(ln_at_url):
    url = "/v1/peers"
    pubkey, host = ln_at_url.split("@")
    data = {"addr": {"pubkey": pubkey, "host": host}}
    lnreq = sendPostRequest(url, data)
    return lnreq


def toSats(btcs):
    return int(btcs * 100000000)


def openChannel(ln_at_url, sats, fee=1, suc=False):
    url = "/v1/channels"
    # apk = f'{pk}'.encode('UTF-8')
    print(connectPeer(ln_at_url))
    pubkey, host = ln_at_url.split("@")
    node_pubkey = base64.b64encode(bytes.fromhex(pubkey)).decode()
    # 'node_pubkey_string': f'{pk}',
    data = {
        # 'node_pubkey_string': f'{pubkey}',
        # This doesnt work but theoretically this is the better way
        "node_pubkey": node_pubkey,
        "spend_unconfirmed": suc,
        "local_funding_amount": f"{sats}",
        "sat_per_byte": f"{fee}",
    }
    print(data)
    lnreq = sendPostRequest(url, data)
    # if 'error' in lnreq.keys():
    # pprint(lnreq)
    try:
        tx_b64 = base64.b64decode(lnreq["funding_txid_bytes"])
        # KEY STEP: You have to reverse the byte order be able to look it up on an explorer
        txid = codecs.encode(bytes(reversed(tx_b64)), "hex")
        print(f"TXID: hex --> { txid } default --> {lnreq['funding_txid_bytes']}\n")
        return txid
    except KeyError:
        error = lnreq["error"]
        print(f"ERROR OPENING CHANNEL:\n\n{error}")
        # Parse out the numbers in the failure, and do something with it
        # d = [float(i) for i in list(map(lambda x: x if x.replace('.', '', 1).isdigit() else print(x),error.split(' '))) if i ]
        # d = list(map(lambda x: int(x*100000000), d))
        print("Unable to openchannel, amount error:")
        f = tuple(
            [toSats(float(s)) for s in error.split() if s.replace(".", "", 1).isdigit()]
        )
        print(f)
        dif = f[0] - f[1]
        print(dif)
        chan_size_w_fee = sats - dif
        print(
            f"Transaction requires {dif} sats Fee. Try a smaller channel size {chan_size_w_fee} next time to use {fee} sat/byte!\n"
        )
        # print(d)
        # print(d[0]-d[1])
        return error


def streamInvoices():
    url = base_url + "/v1/invoices/subscribe"
    r = requests.get(
        url + "?add_index=1", stream=True, headers=headers, verify=cert_path
    )
    for line in r.iter_lines():
        a = json.loads(line.decode("UTF-8"))
        print(a)


def listChanFees(chan_id=None):
    lnreq = sendGetRequest(url14)
    z = pandas.DataFrame(lnreq["channel_fees"])
    z = z.rename(columns={"chan_point": "channel_point"})
    # z = z.set_index("channel_point")
    clist = listChannels()
    clist = clist.rename(columns={"remote_pubkey": "pubkey"})
    # z['chan_id'] = z['channel_point'].apply(lambda x: CP2CID(x,clist) )
    b = getChanPolicy(clist.iloc[0, :].chan_id, clist.iloc[0, :].remote_pubkey)
    # getChanPolicy(a.iloc[0,:].chan_id,)
    print(b)
    c = b.join(z)
    # x = chan_info.join(z).fillna(0)
    return c


# CHANNEL BACKUP
def exportChannelBackup(outfile):
    url = "/v1/channels/backup"
    lnreq = sendGetRequest(url)


# post
def verifyChannelBackup(infile):
    url = "/v1/channels/backup/verify"
    lnreq = sendPostRequest(url)


# post
def importChannelBackup(infile):
    url = "/v1/channels/backup/restore"
    lnreq = sendPostRequest(url)


# System Functions
def getInfo(frame=False):
    url = "/v1/getinfo"
    lnreq = sendGetRequest(url)
    if frame:
        lnframe = pandas.DataFrame(lnreq)
        return lnframe
    return lnreq


def getMyPk():
    info = getInfo()
    mypk = info["identity_pubkey"]
    return mypk


def getBlockHeight():
    return getInfo()["block_height"]
    # return sendGetRequest(url2)['block_height']


def getMyPK():
    return getInfo()["identity_pubkey"]


def getAlias(pubkey, index=True):
    try:
        # Attempt to use index names first
        alias = pkdb[pubkey]
        return alias
    except KeyError as e:
        try:
            lnreq = getNodeInfo(pubkey)
            alias = lnreq["node"]["alias"]
            pkdb.update({pubkey: alias})
            return lnreq["node"]["alias"]
        except KeyError as e:
            print(f"{pubkey} doesn't have an alias? Error: {e}")
            return "NONE/DELETED"


def getNodeInfo(pubkey, channels=False):
    url = f"/v1/graph/node/{pubkey}?include_channels={channels}"
    lnreq = sendGetRequest(url)
    try:
        return lnreq
    except KeyError as e:
        print(f"{pubkey} doesn't have an alias? Error: {e}")
        return "NONE?"
    return lnreq


def getNodeURI(pubkey, clearnet=False):
    """
    Get a connection string for a given node. Will default to a TOR address if available

    pubkey: pubkey of node to get connection string for
    clearnet: whether to override the TOR URL default
    """
    nodeinfo = getNodeInfo(pubkey)
    addresses = nodeinfo["node"]["addresses"]
    addrs = []
    for address in addresses:
        addrs.append(f"{pubkey}@{address['addr']}")
    return addrs


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


def decodePR(pr):
    url = f"/v1/payreq/{pr}"
    lnreq = sendGetRequest(url)
    return lnreq


# Receiving Functions
def addInvoice(amt, memo):
    url = "/v1/invoices"
    data = {"memo": memo, "value": amt, "expiry": "3600"}
    lnreq = sendPostRequest(url, data)
    return lnreq


def lookupInvoice(invoice_rhash):
    lnreq = sendGetRequest(f"/v1/invoice/{invoice_rhash}")
    return lnreq


def lookupInvoice2(invoice_rhash):
    lnreq = sendGetRequest(f"/v1/invoice/", data=invoice_rhash)
    return lnreq


def openInvoices():
    invoices = listInvoices(pending=True)
    invoices.value_msat = invoices.value_msat.astype(int)
    return invoices


def listPayments():
    url = "/v1/payments"
    lnreq = sendGetRequest(url)
    payments = pandas.DataFrame(lnreq["payments"])


def listInvoices(max_invs=5000, offset=0, pending=False):
    url = "/v1/invoices"
    lnreq = sendGetRequest(
        url
        + f"?num_max_invoices={max_invs}&index_offset={offset}&pending_only={pending}"
    )
    df = pandas.DataFrame(lnreq["invoices"])
    print("Available Data Columns: ")
    print(df.columns)
    df = df.fillna("0")
    # print(df[['memo','amt_paid_sat','state','settled','creation_date','settle_date','r_preimage']])
    df["creation_date_h"] = df.apply(
        lambda x: datetime.fromtimestamp(int(x["creation_date"]))
        if int(x["settle_date"]) != 0
        else 0,
        axis=1,
    )
    df["settle_date_h"] = df.apply(
        lambda x: datetime.fromtimestamp(int(x["settle_date"]))
        if int(x["settle_date"]) != 0
        else 0,
        axis=1,
    )
    # df['alias'] = Series(b).apply(lambda x: getAlias(x), axis=1 )
    # b= list(a.index)
    base_columns = [
        "memo",
        "r_hash",
        "value_msat",
        "creation_date_h",
        "state",
        "settled",
        "settle_date_h",
        "amt_paid_sat",
        "amt_paid_msat",
    ]
    return df[base_columns]
    # return df[['memo','amt_paid_sat','state','creation_date_h','settle_date_h','htlcs']]
    # datetime.fromtimestamp(x['creation_date'])


# def getForwards(start,end):
def getForwards(days_past=30):
    start = int((datetime.now() - timedelta(days=days_past)).timestamp())
    end = int(datetime.now().timestamp())
    data = {"start_time": start, "end_time": end, "num_max_events": 10000}
    url = "/v1/switch"
    lnreq = sendPostRequest(url, data)
    fwd_frame = pandas.DataFrame(lnreq["forwarding_events"])
    # Convert Timestamp to nice datetime
    fwd_frame["dt"] = fwd_frame["timestamp"].apply(
        lambda x: datetime.fromtimestamp(int(x))
    )
    fwd_frame["dts"] = fwd_frame.dt.astype("str")
    print(
        f'Number of Satoshi Made This Month: {pandas.to_numeric(fwd_frame["fee_msat"]).sum()/1000}!'
    )
    print(
        f'AVG Number of Satoshi Made Per Day: {pandas.to_numeric(fwd_frame["fee_msat"]).sum()/1000/days_past}!'
    )
    # TODO keep track of rebalance fees
    # a['settle_date_h']=a['settle_date_h'].astype('str')
    # a.query(f'settle_date_h.str.contains("2020-11-19")')
    return fwd_frame


def fwdsToday(ff):
    fwds = ff.query(f'dts.str.contains("{datetime.now().strftime("%Y-%m-%d")}")').shape[
        0
    ]
    return fwds


# for i in range(30,-1,-1):
# 	fwdsStats(a,i)
def fwdsStats(ff, days_ago=0):
    day_str = (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
    day_fwds = ff.query(f'dts.str.contains("{day_str}")')
    day_fwds_count = ff.query(f'dts.str.contains("{day_str}")').shape[0]
    avg_fees = day_fwds.fee_msat.astype("float").mean()
    avg_forward = day_fwds.amt_in.astype("float").mean()
    return {
        "event_day": day_str,
        "count": day_fwds_count,
        "avg_fees": avg_fees,
        "avg_forward": avg_forward,
    }


def fwdByDay(ff, days_past=30):
    # datetime.strptime('2020-04-04','%Y-%m-%d')
    t = datetime.now().date() - timedelta(days_past)
    t.strftime("%Y-%m-%d")
    results = []
    # TODO: look into this logic a bit
    for i in range(0, days_past + 1):
        num_fwds = ff.query(f'dts.str.contains("{t.strftime("%Y-%m-%d")}")').shape[0]
        fees = (
            ff.query(f'dts.str.contains("{t.strftime("%Y-%m-%d")}")')
            .fee_msat.astype("float")
            .sum()
            / 1000
        )
        results.append((t.strftime("%Y-%m-%d"), num_fwds, fees))
        t += timedelta(days=1)
    rframe = pandas.DataFrame(results)
    rframe.columns = ["date", "forwards", "sats_earned"]
    return rframe


# TODO: fix me, and figure out arrays!
def queryRoute(
    src_pk, dest_pk, oid=None, lh=None, pay_amt=123, ignore_list=None, frame=False
):
    # base64.b64encode(bytes.fromhex(last_hop_pubkey)).decode()
    c = listChannels()
    c["pk64"] = c["remote_pubkey"].apply(
        lambda x: base64.urlsafe_b64encode(bytes.fromhex(x)).decode()
    )
    # outgoing_chan_id
    # last_hop_pubkey
    # Convert HEX pubkeys to to base64
    # for node in ignore_list:
    # 	ig64 = base64.b64encode(bytes.fromhex(node)).decode().replace('+','-').replace('/','_')
    # 	id_url_safe = ignore
    # 	id_percent_encoded = urllib.parse.quote(id_url_safe)
    target_url = f"/v1/graph/routes/{dest_pk}/{pay_amt}?source_pub_key={src_pk}"
    target_url += (
        f"&use_mission_control=false&final_cltv_delta=40&fee_limit.fixed_msat=444000"
    )
    # target_url + f"&ignored_nodes="
    if lh:
        target_url + f"&last_hop_pubkey={lh}"
    if oid:
        target_url + f"&outgoing_chan_id={oid}"
    lnreq = sendGetRequest(target_url)
    if frame:
        f = lnreq["routes"][0]
        f["total_fees_msat"] = "0"
        f["total_fees"] = "0"
        return f
    hops = lnreq["routes"][0]["hops"]
    hoplist = []
    for hop in hops:
        hoplist.append(hop)
    # It only ever returns 1 route
    return lnreq["routes"][0]["hops"]


# ON-CHAIN
def showFunds():
    chain_funds_url = "/v1/balance/blockchain"
    on = sendGetRequest(chain_funds_url)
    offchain_funds_url = "/v1/balance/channels"
    off = sendGetRequest(offchain_funds_url)
    data = {"on-chain": on, "off-offchain": off}
    print(f"On-Chain: {on}\t Off-Chain: {off}")
    channels = listChannels()
    a = channels.local_balance.sum() + channels.remote_balance.sum()
    b = channels.local_balance.sum()
    print(f"Total Remote Balance: {a}")
    print(f"Total Local Balance {b}")
    print(f"Local to remote ratio: {b/a}")
    print(data)
    funds_frame = pandas.DataFrame(data)
    return funds_frame


def listCoins(min_confs=0, show_columns=False, add_columns=None):
    url = f"/v1/utxos?min_confs={min_confs}&max_confs={getBlockHeight()}"
    # url = f'/v1/utxos'
    lnreq = sendGetRequest(url)

    print(f"Received message: {pformat(lnreq)}")
    # Guard Clause
    if "utxos" not in lnreq.keys():
        print("No UTXOs available")
        return

    lnframe = pandas.DataFrame(lnreq["utxos"])

    default_columns = ["address_type", "address", "amount_sat", "confirmations"]
    if add_columns != None:
        default_columns = default_columns + add_columns
    if show_columns:
        print(lnframe.columns)
    return lnframe[default_columns]


def listChainTxns(show_columns=False, add_columns=None):
    url = "/v1/transactions"
    lnreq = sendGetRequest(url)
    lnframe = pandas.DataFrame(lnreq["transactions"])
    lnframe["ts_h"] = lnframe.apply(
        lambda x: datetime.fromtimestamp(int(x["time_stamp"])), axis=1
    )
    default_columns = [
        "ts_h",
        "num_confirmations",
        "amount",
        "tx_hash",
        "total_fees",
        "label",
    ]
    if add_columns != None:
        default_columns = default_columns + add_columns
    if show_columns:
        print(lnframe.columns)

    # Reverse the order
    return lnframe[default_columns][::-1]


def sendCoins(addr, amt, feerate=3, toself=False):
    url = "/v1/transactions"
    if toself:
        addr = getNewAddress()
    # either target_conf or sat_per_byte used at one time
    data = {
        # 'target_conf': 20,
        "sat_per_byte": feerate,
        "send_all": False,
        "addr": f"{addr}",
        "amount": f"{amt}",
        "spend_unconfirmed": True,
    }
    lnreq = sendPostRequest(url, data)
    return lnreq


# Need websockets to do this nicely!
def closeChannel(channel_point, output_index=0, fee_rate=2, force=False):
    url = f"/v1/channels/{channel_point}/{output_index}?force={force}&sat_per_byte={fee_rate}"
    x = sendDeleteRequest(url)
    return x
    # DELETE /v1/channels/{channel_point.funding_txid_str}/{channel_point.output_index}


def closedChannels():
    url = "/v1/channels/closed"
    lnreq = sendGetRequest(url)
    c = pandas.DataFrame(lnreq["channels"])
    closed_channels = c[
        [
            "remote_pubkey",
            "close_type",
            "open_initiator",
            "settled_balance",
            "close_height",
            "close_initiator",
        ]
    ]
    closed_channels["alias"] = closed_channels.apply(
        lambda x: getAlias(x.remote_pubkey), axis=1
    )
    return closed_channels


def main():
    print(f"Welcome to the LN: [bold cyan]{getMyAlias()}[/bold cyan].")
    print(listChannels())
    print("[green]****[/green] [yellow]MUST IMPORT[/yellow] [green]****[/green] ...")
    print("[bold yellow]from lnd_pyshell.lnd_rest import *[/bold yellow]")
    print("[bold yellow]from lnd_pyshell.utils import *[/bold yellow]")
    print("[bold yellow]from lnd_pyshell.rebalance import *[/bold yellow]")
    print("[bold yellow]from time import sleep[/bold yellow]")
    code.interact(local=locals())


if __name__ == "__main__":
    main()
