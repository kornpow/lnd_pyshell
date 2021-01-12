# utils.py
from lnd_pyshell.lnd_rest import getAlias, getMyPK, getAlias
from lnd_pyshell.channels import getChanPoint, getEdgeInfo

# Channel Point to Channel Id
def CP2CID(chan_point, chan_list):
    """
    TODO?
    """
    pass
    # chan_list.reset_index(inplace = True)
    # a = chan_list[channel_point==chan_point]
    # return a.chan_id


def CID2CP(chanid):
    cp = getChanPoint(chanid)
    return cp


def CID2ListPK(chanid):
    try:
        lnreq = getEdgeInfo(chanid)
        list_pks = lnreq[['node1_pub','node2_pub']].values.tolist()[0]
        # list_pks = [lnreq[akey] for akey in ["node1_pub", "node2_pub"]]
        return list_pks
    except KeyError as e:
        print("Missing Edge??")
        return ["", ""]


def CID2Alias(chanid):
    """
    Convert a channel ID to an alias
    *** ONLY WORKS WITH CHANNEL PARTNERS TO YOUR OWN NODE ***
    """
    return getAlias(list(set(CID2ListPK(chanid)) - set([getMyPK()]))[0])


def toSats(btcs):
    return int(btcs * 100000000)

def toBTCs(sats):
    return sats / 1e8