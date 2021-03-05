from datetime import datetime, timedelta
import pandas
from random import randint
from pprint import pprint
import base64
import json

# SRC IMPORTS
from lnd_pyshell.base_requests import *


def streamInvoices():
    url = base_url + "/v1/invoices/subscribe"
    r = requests.get(
        url + "?add_index=1", stream=True, headers=headers, verify=cert_path
    )
    for line in r.iter_lines():
        a = json.loads(line.decode("UTF-8"))
        print(a)

def rebalanceInvoice(amt_min,amt_max,max_active_invoices=5):
    """
    Get a random specially marked valid invoice in a specific range.
    If an valid invoice does not exist, create a new one.
    """
    amt_min_msat = amt_min * 1000
    amt_max_msat = amt_max * 1000
    c = listInvoices(max_invs=5, offset=0, pending=False)
    c = c.query('memo == "rebalance" and state == "OPEN"')
    # If no valid invoices available, create one
    if c.empty:
        print("No invoices available, creating a new payment request!")
        amount = randint(amt_min, amt_max)
        addInvoice(amount, "rebalance")
    if c.shape[0] < 5:
        print("Less than max invoices available, creating a new payment request!")
        amount = randint(amt_min, amt_max)
        addInvoice(amount, "rebalance")       
    # Do some conversions and filterings
    c = listInvoices(max_invs=5, offset=0, pending=False)
    c['value_msat'] = c.value_msat.astype('int')
    c = c.query('memo == "rebalance" and state == "OPEN"')
    c = c.query("@amt_min_msat < value_msat < @amt_max_msat")
    # Get the desired rhash and find the pay req that goes with it
    selection = c.sample()
    rhash = selection.r_hash.item()
    amt = selection.value_msat.item() / 1000
    inv = lookupInvoice(rhash)
    return inv["payment_request"], amt

#broken?
# Receiving Functions
def addInvoice(amt, memo,expiry=3600):
    url = "/v1/invoices"
    test = "3600"
    data = {"memo": memo, "value": amt, "expiry": str(expiry)}
    lnreq = sendPostRequest(url, data)
    return lnreq


def lookupInvoice(invoice_rhash):
    rhash = base64.urlsafe_b64encode(base64.b64decode(invoice_rhash)).decode()
    url = f"/v1/invoice/?r_hash={rhash}"
    print(f"URL: {url}")
    lnreq = sendGetRequest(url)
    return lnreq


def openInvoices():
    invoices = listInvoices(pending=True)
    invoices.value_msat = invoices.value_msat.astype(int)
    return invoices


def listInvoices(max_invs=5000, offset=0, pending=False):
    url = "/v1/invoices"
    lnreq = sendGetRequest(
        url
        + f"?num_max_invoices={max_invs}&index_offset={offset}&pending_only={pending}&reversed=true"
    )
    df = pandas.DataFrame(lnreq["invoices"])
    print("Available Data Columns: ")
    print(df.columns)
    df = df.fillna("0")
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