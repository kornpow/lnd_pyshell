import os
import codecs
import base64
import io

# *** Find minimal permissions to operate ***
# lncli listpermissions

# *** Required Permissions ***
permissions = [
    "uri:/lnrpc.Lightning/LookupInvoice",
    "uri:/lnrpc.Lightning/ListInvoices",
    "uri:/lnrpc.Lightning/DecodePayReq",
    "uri:/lnrpc.Lightning/AddInvoice"
]
bake_file = "chaos.macaroon"
print(f"lncli bakemacaroon --save_to {bake_file} {' '.join(permissions)}")

# *** TLS ***
# Default in ASCII format
with open("tls.cert","rb") as f:
    tls_raw = f.read()

tls_hex = codecs.encode(tls_raw,'hex')

# *** MACAROON ***
# Default in byte format
with open(f"data/chain/bitcoin/mainnet/{bake_file}","rb") as f:
    mac_raw = f.read()

mac_hex = codecs.encode(mac_raw,'hex')


print(f"TLS Cert: {tls_hex}")

print(f"Macaroon: {mac_hex}")