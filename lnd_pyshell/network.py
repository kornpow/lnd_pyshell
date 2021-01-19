# network.py
import pandas
from lnd_pyshell.base_requests import *
from lnd_pyshell.channels import *

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