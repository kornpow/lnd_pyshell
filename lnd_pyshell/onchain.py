import os

# ON-CHAIN
def createWallet():
    url = "/v1/initwallet"
    data["wallet_password"] = None
    data["cipher_seed_mnemonic"] = None
    data["aezeed_passphrase"] = None

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