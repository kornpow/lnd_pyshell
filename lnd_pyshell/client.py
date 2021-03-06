import random
import string
import time
from typing import List, Union
from urllib.parse import urljoin
import os

import os
import code

import utils
from exceptions import handle_error_response
from session import LNDAPISession



class LNDRestAPI(object):
    # TODO: Update these variables
    def __init__(self, host=None, macaroon=None, certfile=None):
        """
        Instantiate a new API client.
        Args:
            macaroon (hex str): Hex encoded "passcode" to operate LND.
            certfile (hex str): Path to certificate file to verify for TLS
                connections (mostly untested).
        """

        if host == None:
            self.host = "https://" + os.getenv("NODE_IP") + ":8080"

        self.session = LNDAPISession()

        self.session.init_auth()

    def url(self, path):
        return urljoin(self.host, path)

    @staticmethod
    def _xact_name():
        return "TX_{}".format("".join(random.choices(string.ascii_uppercase + string.digits, k=6)))

    def get_connection_info(self):
        print(f"Host: {self.host}")

    def get(self, endpoint):
        return self._request("GET",endpoint)

    def post(self, endpoint, data):
        return self._request("POST",endpoint,data)

    def _request(self, method, url, data={}, request_id: int = 0):
        resp = self.session.request(method, self.url(url), json=data)

        if resp.status_code >= 400:
            handle_error_response(resp)

        return resp.json()


if __name__ == "__main__":
    a = LNDRestAPI()
    a.get_connection_info()
    # code.interact(locals=local())