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
