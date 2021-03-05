import os
from datetime import datetime, timedelta
import base64
import json

import pandas

from lnd_pyshell.base_requests import *
from lnd_pyshell.channels import listChannels




def decodePR(pr):
    url = f"/v1/payreq/{pr}"
    lnreq = sendGetRequest(url)
    return lnreq


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



def listPayments():
    url = "/v1/payments"
    lnreq = sendGetRequest(url)
    payments = pandas.DataFrame(lnreq["payments"])



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
