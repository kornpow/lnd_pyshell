# network.py
import pandas
from lnd_pyshell.base_requests import *
from lnd_pyshell.channels import *


def getMyAlias():
    myalias = getAlias(getMyPK())
    return myalias


def getInfo(frame=False):
    url = "/v1/getinfo"
    lnreq = sendGetRequest(url)
    if frame:
        lnframe = pandas.DataFrame(lnreq)
        return lnframe
    return lnreq


def getMyPK():
    return getInfo()["identity_pubkey"]


def getAlias(pubkey, index=True):
    try:
        # Attempt to use index names first
        pkdb1 = {}
        alias = pkdb1[pubkey]
        yield alias
    except KeyError as e:
        try:
            lnreq = getNodeInfo(pubkey)
            alias = lnreq["node"]["alias"]
            pkdb.update({pubkey: alias})
            yield lnreq["node"]["alias"]
        except KeyError as e:
            print(f"{pubkey} doesn't have an alias? Error: {e}")
            yield "NONE/DELETED"


def connectPeer(ln_at_url):
    url = "/v1/peers"
    pubkey, host = ln_at_url.split("@")
    data = {"addr": {"pubkey": pubkey, "host": host}}
    lnreq = sendPostRequest(url, data)
    return lnreq


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