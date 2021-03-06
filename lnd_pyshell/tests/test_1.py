import os
from pprint import pprint
from client import LNDRestAPI

def test_host_setup():
    a = LNDRestAPI()

    assert a.host.startswith("https://")
    assert a.host.endswith(":8080")