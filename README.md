# LND_pyshell

## Dependancies
```
# Create Python Virtual Environment
python3 -m venv env
# Enter Environment
source env/bin/activate
# Install Python dependancies
pip3 install pandas requests
```

## Usage Instructions
```
python3 lnd_rest.py
# or, if ./node_scripts is added to $PATH
lnd_pyshell
```

## Environment Variables
```
# Add scripts to System PATH
export PATH=$PATH:{directory to lnd_pyshell}/lnd_pyshell/node_scripts
# Specify that node is running locally
export NODE_IP=0.0.0.0
# or Specify that node is running remotely
export NODE_IP=123.456.789.101
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

## Non-Local Node Usage
1. In order to support non-local node usage, sshfs is used.
1. Use the ```cloud_mount``` command to mount your LND directory at /home/{user}/.lnd