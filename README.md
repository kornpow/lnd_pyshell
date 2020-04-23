# LND_pyshell

## Dependancies
```
# Create Python Virtual Environment
python3 -m venv env
# Enter Environment
source env/bin/activate
```

## Usage Instructions

## Environment Variables
export NODE_IP=0.0.0.0

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