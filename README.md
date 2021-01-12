# LND_pyshell

## Install
```
pip3 install git+https://github.com/sako0938/lnd_pyshell.git
```

## Use
```python
from lnd_pyshell.lnd_rest import *
from lnd_pyshell.utils import *
from lnd_pyshell.rebalance import *
from time import sleep

# get list of channels
c = listChannels()

# use a pandas query on the channel list!
# *** find large channels with low balances ***
c.query('local_balance <= 3000000 & capacity >= 4000000')

# *** find channels that are balanced ***
c.query('balanced > 0.4 & balanced < 0.6')
```
## Development
Uses the awesome poetry package manager!
```
poetry shell
poetry install
poetry run lnd_pyshell
```


## Dependancies
```
# Install SSHFS, this utility mounts remote filesystems locally to a file
sudo apt install sshfs


# Create Python Virtual Environment
python3 -m venv env


# Enter Environment
source env/bin/activate


# Install Python dependancies
pip3 install pandas requests
```

## Obtain Base64 Encoded Credentials
cat ~/.lnd/tls.cert | base 64 -w 0
cat ~/.lnd/data/chain/bitcoin/mainnet/readonly.macaroon | base 64 -w 0

## Usage Instructions
```bash
python3 lnd_rest.py
# or, if ./node_scripts is added to $PATH
lnd_pyshell
```

## Environment Variables
```bash
# Add scripts to System PATH
export PATH=$PATH:{directory to lnd_pyshell}/lnd_pyshell/node_scripts


# Specify that your node is running locally
export NODE_IP=0.0.0.0


# or Specify that your node is running remotely
export NODE_IP=123.456.789.101

# Specify which macaroon to use, else looks in the default location
export MAC={MACAROON CONVERTED TO HEX STRING}

# Specify which TLS cert to use, else looks in the default location
export TLS={TLS CERT CONVERTED TO HEX STRING}
```

## LND.conf
LND must be configured to use the REST API:
```
[Application Options]
...
...
restlisten=0.0.0.0:8080
...
...
[Bitcoin]
```

## Command Structure
Run ```python3 lnd_rest.py```

It will open up inside a Python shell:
```python
# Useful Commands:

# Basic info
getInfo()


# Get on-chain and off-chain balance
showFunds()


# Get list of all channels
listChannels()


# List all on-chain transactions
listChainTxns()


# Get a new On-Chain Address
getNewAddress()


# Open a channel to a node
openChannel('pubkey@192.168.1.1:9735',1000000,1)
# Open channel using an un-confirmed output
openChannel('pubkey@192.168.1.1:9735',1000000,1,suc=True)


# Send Payment to Payment Request
pr = 'lntb...'
sendPaymentByReq(pr)


# Create New Invoice
invoice = addInvoice(100,'testinvoice')


# Rebalance Channels
oid = '123123123123'
lh = 'lasthoppubkey'
fees_limit_msat = 4200
rebalance(100000,oid,lh,fees_limit_msat)


# Get information about a node by pubkey
pk = '{node_pubkey}'
getNodeInfo(pk)


# Get Node Alias
getAlias(pk)


# Get forwarded transactions
# and the count number of transactions per day
a = getForwards()
fwdByDay(a)


# Get Specific Fee Info About a channel
chan_id = '{channel id}'
getChanPolicy(chan_id)

```
## Non-Local Node Usage
1. In order to support non-local node usage, sshfs is used.
1. Use the ```cloud_mount``` command to mount your LND directory at /home/{user}/.lnd


## Building Wheels With Poetry
poetry build -vvv
poetry shell
pip3 install dist/lnd_pyshell-0.1.5.tar.gz
lnd_pyshell