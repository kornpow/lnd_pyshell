import base64
import pandas
from lnd_pyshell.base_requests import sendGetRequest, sendPostRequest
from lnd_pyshell.lnd_rest import getAlias


def getChanPoint(chanid):
	lnreq = getEdgeInfo(chanid)
	cp = lnreq['chan_point']
	return cp

def getEdgeInfo(chanid):
    """
    """
    url = f"/v1/graph/edge/{chanid}"
    lnreq = sendGetRequest(url)
    lnreq.pop("node1_policy")
    lnreq.pop("node2_policy")
    a = pandas.DataFrame(lnreq,index=[0])
    return a

def openChannel(ln_at_url, sats, fee=1, suc=False):
    url = "/v1/channels"
    # apk = f'{pk}'.encode('UTF-8')
    print(connectPeer(ln_at_url))
    pubkey, host = ln_at_url.split("@")
    node_pubkey = base64.b64encode(bytes.fromhex(pubkey)).decode()
    # 'node_pubkey_string': f'{pk}',
    data = {
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
        txid = codecs.encode(bytes(reversed(tx_b64)), "hex").decode()
        print(f"TXID: hex --> { txid } base64 --> {lnreq['funding_txid_bytes']}\n")
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




def listChannels(chanpoint=None, all=False, disabled=False, private=False):
    def getBalance(row):
        return row["local_balance"] / (row["local_balance"] + row["remote_balance"])
    def getChanSize(row):
        return row["local_balance"] + row["remote_balance"]
    def getToBalance(row, target=500000):
        return target - row["local_balance"]
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

### *** CLOSED/CLOSING CHANNELS ***
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


### *** CHANNEL BACKUP ***
def exportChannelBackup(outfile):
    url = "/v1/channels/backup"
    lnreq = sendGetRequest(url)
    backup = json.dumps(lnreq)
    with open(outfile,'w') as f:
        f.write(backup)


# post
def verifyChannelBackup(infile):
    url = "/v1/channels/backup/verify"
    with open(infile,'r') as f:
        backup = f.read()
        b = json.loads(backup)
        c = b['single_chan_backups']
        d = b['single_chan_backups']['chan_backups'][0]
    lnreq = sendPostRequest(url,{'single_chan_backups': c['chan_backups']})


# post
def importChannelBackup(infile):
    url = "/v1/channels/backup/restore"
    lnreq = sendPostRequest(url)
    with open(infile,'r') as f:
        backup = f.read()
        b = json.loads(backup)