from datetime import datetime, timedelta
import pandas
from random import randint
from pprint import pprint
import base64

# SRC IMPORTS
from lnd_pyshell.base_requests import *


def rebalanceInvoice(amt_min,amt_max):
    """
    Get a random specially marked valid invoice in a specific range.
    If an valid invoice does not exist, create a new one.
    """
    amt_min_msat = amt_min * 1000
    amt_max_msat = amt_max * 1000
    c = listInvoices(max_invs=5, offset=0, pending=False)
    c = c.query('memo == "rebalance" and state == "OPEN"')
    c['value_msat'] = c.value_msat.astype('int')
    c = c.query("@amt_min_msat < value_msat < @amt_max_msat")
    if not c.empty:
        c.sample()
    else:
        amount = randint(amt_min, amt_max)
        addInvoice(amount, "rebalance")
        c.sample()
    return 

# Receiving Functions
def addInvoice(amt, memo,expiry=3600):
    url = "/v1/invoices"
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
    # print(df[['memo','amt_paid_sat','state','settled','creation_date','settle_date','r_preimage']])
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
    # df['alias'] = Series(b).apply(lambda x: getAlias(x), axis=1 )
    # b= list(a.index)
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
    # return df[['memo','amt_paid_sat','state','creation_date_h','settle_date_h','htlcs']]
    # datetime.fromtimestamp(x['creation_date'])