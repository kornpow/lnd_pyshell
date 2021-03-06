import os
from client import LNDRestAPI
from pprint import pprint, pformat

#ACCESS LND API
def getNodeInfo(pubkey, channels=False):
    a = LNDRestAPI()
    url = f"/v1/graph/node/{pubkey}?include_channels={channels}"
    lnreq = a.get(url)
    try:
        return lnreq
    except KeyError as e:
        print(f"{pubkey} doesn't have an alias? Error: {e}")
        return "NONE?"
    return lnreq

def getInfo(frame=False):
    a = LNDRestAPI()
    url = "/v1/getinfo"
    lnreq = a.get(url)
    if frame:
        lnframe = pandas.DataFrame(lnreq)
        return lnframe
    return lnreq



def listChannels(chanpoint=None, all=False, disabled=False, private=False):
    a = LNDRestAPI()
    def getBalance(row):
        return row["local_balance"] / (row["local_balance"] + row["remote_balance"])
    def getChanSize(row):
        return row["local_balance"] + row["remote_balance"]
    def getToBalance(row, target=500000):
        return target - row["local_balance"]
    url = "/v1/channels"
    if private:
        url += "?private_only=true"
    # Perform
    lnreq = a.get(url)
    # Check if no channels
    if not lnreq["channels"]:
        print("No Channels Available!")
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


def showFunds():
    a = LNDRestAPI()
    chain_funds_url = "/v1/balance/blockchain"
    on = a.get(chain_funds_url)
    offchain_funds_url = "/v1/balance/channels"
    off = a.get(offchain_funds_url)
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
    a = LNDRestAPI()
    url = f"/v1/utxos?min_confs={min_confs}&max_confs={getBlockHeight()}"
    lnreq = a.get(url)
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



# ***** NON-API *****
def getMyAlias():
    myalias = getAlias(getMyPK())
    return myalias

def getBlockHeight():
    return getInfo()["block_height"]

def getMyPK():
    return getInfo()["identity_pubkey"]


# ****** FEE INFO ******
def updateChanPolicy(chan_point=None, fee_rate=0.000001, base_fee_msat=300, tld=40, min_htlc=None):
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