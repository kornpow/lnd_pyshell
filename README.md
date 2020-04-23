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
export NODE_IP=0.0.0.0
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