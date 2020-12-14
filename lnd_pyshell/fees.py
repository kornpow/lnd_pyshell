from lnd_pyshell.lnd_rest import *
from lnd_pyshell.utils import *
from lnd_pyshell.rebalance import *
from time import sleep


def calcBreakEvenFee(chanid, amt):
    """
    calculate the max fee for a channel that you can pay in order to break-even routing payments.
    """


mypk = getMyPK()
policy = getChanPolicy(chanid)
otherparty = policy.query(f"pubkey !=  @mypk")
fee_rate = int(otherparty.fee_rate_milli_msat.item()) * 1e-06
base_fee = int(otherparty.fee_base_msat.item()) / 1000
last_hop_fee = (fee_rate * amt) + base_fee
print(f"Last Hop Fee: {last_hop_fee}")

CID2ListPK(chanid)


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