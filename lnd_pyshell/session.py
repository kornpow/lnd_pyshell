from base64 import b64encode
from requests import Session
import urllib3
import codecs
import os
import io
import tempfile

class LNDAPISession(Session):

    def __init__(self, *args, **kwargs):
        """
        Creates a new CoreAPISession instance.
        """
        super(LNDAPISession, self).__init__(*args, **kwargs)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.headers.update({
            'Accept-Charset': 'utf-8',
            'Content-Type': 'text/plain',
        })

        self.mac = None
        self.tls = None
        self.verify = None

    def init_auth(self):
        mac = os.getenv("MAC","error")
        tls = os.getenv("TLS","error")
        if "error" in [mac, tls]:
            print("Environment variable issue.")
        
        self.mac = mac
        self.tls = tls
        self.init_mac()
        self.init_tls()

    def init_mac(self):
        self.headers.update({
            "Grpc-Metadata-macaroon": self.mac
        })

    def init_tls(self):
        cert_bytes = bytes.fromhex(self.tls)
        fp = tempfile.NamedTemporaryFile(delete=False)
        fn = fp.name
        fp.write(cert_bytes)
        fp.seek(0)
        cert_path = fn
        f = io.StringIO(codecs.decode(self.tls, encoding="hex").decode())
        self.verify = cert_path
    

__all__ = ['LNDAPISession']