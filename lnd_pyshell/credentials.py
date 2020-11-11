import os
import codecs
import base64
import io


# *** TLS ***
# Default in ASCII format
with open("tls.cert","rb") as f:
    tls_raw = f.read()

tls_hex = codecs.encode(tls_raw,'hex')

# *** MACAROON ***
# Default in byte format
with open("data/chain/bitcoin/mainnet/invoice.macaroon","rb") as f:
    mac_raw = f.read()

mac_hex = codecs.encode(mac_raw,'hex')


print(f"TLS Cert: {tls_hex}")

print(f"Macaroon: {mac_hex}")