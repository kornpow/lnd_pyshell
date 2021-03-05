endpoints = [

]

GET /v1/balance/blockchain
GET /v1/balance/channels
GET /v1/channels
GET /v1/channels/backup
GET /v1/channels/backup/{chan_point.funding_txid_str}/{chan_point.output_index}
GET /v1/channels/backup/subscribe
GET /v1/channels/closed
GET /v1/channels/pending
GET /v1/fees
GET /v1/getinfo
GET /v1/getrecoveryinfo
GET /v1/graph
GET /v1/graph/edge/{chan_id}
GET /v1/graph/info
GET /v1/graph/node/{pub_key}
GET /v1/graph/nodemetrics
GET /v1/graph/routes/{pub_key}/{amt}
GET /v1/invoice/{r_hash_str}
GET /v1/invoices
GET /v1/macaroon/ids
GET /v1/macaroon/permissions
GET /v1/newaddress
GET /v1/payments
GET /v1/payreq/{pay_req}
GET /v1/peers
GET /v1/transactions
GET /v1/transactions/fee
GET /v1/utxos
GET /v1/genseed
GET /v2/router/mc
GET /v2/router/mc/probability/{from_node}/{to_node}/{amt_msat}
GET /v2/router/mccfg
GET /v2/versioner/version
GET /v2/watchtower/server
GET /v2/wallet/estimatefee/{conf_target}
GET /v2/wallet/sweeps
GET /v2/wallet/sweeps/pending
GET /v2/autopilot/scores
GET /v2/autopilot/status
GET /v2/watchtower/client
GET /v2/watchtower/client/info/{pubkey}
GET /v2/watchtower/client/policy
GET /v2/watchtower/client/stats




POST /v1/channels
POST /v1/channels/backup/restore
POST /v1/channels/backup/verify
POST /v1/channels/stream
POST /v1/channels/transactions
POST /v1/channels/transactions/route
POST /v1/chanpolicy
POST /v1/debuglevel
POST /v1/funding/step
POST /v1/invoices
POST /v1/macaroon
POST /v1/peers
POST /v1/signmessage
POST /v1/stop
POST /v1/switch
POST /v1/transactions
POST /v1/transactions/many
POST /v1/verifymessage
POST /v1/changepassword
POST /v1/initwallet
POST /v1/unlockwallet
POST /v2/invoices/cancel
POST /v2/invoices/hodl
POST /v2/invoices/settle
POST /v2/router/mc/reset
POST /v2/router/route
POST /v2/router/route/estimatefee
POST /v2/router/route/send
POST /v2/signer/inputscript
POST /v2/signer/sharedkey
POST /v2/signer/signmessage
POST /v2/signer/signraw
POST /v2/signer/verifymessage
POST /v2/wallet/address/next
POST /v2/wallet/bumpfee
POST /v2/wallet/key
POST /v2/wallet/key/next
POST /v2/wallet/psbt/finalize
POST /v2/wallet/psbt/fund
POST /v2/wallet/send
POST /v2/wallet/tx
POST /v2/wallet/tx/label
POST /v2/wallet/utxos
POST /v2/wallet/utxos/lease
POST /v2/wallet/utxos/release
POST /v2/autopilot/modify
POST /v2/watchtower/client



DELETE /v1/channels/{channel_point.funding_txid_str}/{channel_point.output_index}
DELETE /v1/channels/abandon/{channel_point.funding_txid_str}/{channel_point.output_index}
DELETE /v1/macaroon/{root_key_id}
DELETE /v1/payments
DELETE /v1/peers/{pub_key}
DELETE /v2/watchtower/client/{pubkey}


STREAM:
GET /v1/channels/subscribe
GET /v1/graph/subscribe
GET /v1/invoices/subscribe
GET /v1/peers/subscribe
GET /v1/transactions/subscribe
GET /v2/invoices/subscribe/{r_hash}
GET /v2/router/htlcevents
POST /v2/router/send
GET /v2/router/track/{payment_hash}
POST /v2/chainnotifier/register/blocks
POST /v2/chainnotifier/register/confirmations
POST /v2/chainnotifier/register/spends