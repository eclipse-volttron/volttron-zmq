from pathlib import Path
import json

import zmq.green as zmq
from zmq.utils import z85
import zmq.auth
import base64
import binascii
from volttron.client.known_identities import CONTROL_CONNECTION


def encode_key(key):
    '''Base64-encode and return a key in a URL-safe manner.'''
    # There is no easy way to test if key is already base64 encoded and ASCII decoded. This seems the best way.
    if len(key) % 4 != 0:
        return key
    key = key if isinstance(key, bytes) else key.encode("utf-8")
    try:
        assert len(key) in (32, 40)
    except AssertionError:
        raise AssertionError("Assertion error while encoding key:{}, len:{}".format(key, len(key)))
    if len(key) == 40:
        key = z85.decode(key)
    return base64.urlsafe_b64encode(key)[:-1].decode("ASCII")


def decode_key(key):
    '''Parse and return a Z85 encoded key from other encodings.'''
    if isinstance(key, str):
        key = key.encode("ASCII")
    length = len(key)
    if length == 40:
        return key
    elif length == 43:
        return z85.encode(base64.urlsafe_b64decode(key + '='.encode("ASCII")))
    elif length == 44:
        return z85.encode(base64.urlsafe_b64decode(key))
    elif length == 54:
        return base64.urlsafe_b64decode(key + '=='.encode("ASCII"))
    elif length == 56:
        return base64.urlsafe_b64decode(key)
    elif length == 64:
        return z85.encode(binascii.unhexlify(key))
    elif length == 80:
        return binascii.unhexlify(key)
    raise ValueError('unknown key encoding')

ctx = zmq.Context.instance()

#address = 'ipc://@/home/os2204/.volttron_redo/run/vip.socket'
#address = 'tcp://127.0.0.1:22916'

volttron_home = '/home/os2204/.volttron_redo'
#volttron_home = '/home/os2204/.volttron_original'

address = 'ipc://@' + str(Path(volttron_home) / "run/vip.socket")
cred_path = Path(volttron_home) / "credentials_store/control.connection.json"
#cred_path = (Path(volttron_home) / "keystores/control.connection/keystore.json")
server_cred_path = Path(volttron_home) / "credentials_store/platform.json"
#server_cred_path = Path(volttron_home) / "keystore"

cred_key_store = json.loads(cred_path.read_text())
if 'publickey' not in cred_key_store:
    cred_key_store['publickey'] = cred_key_store['public']
    cred_key_store['secretkey'] = cred_key_store['secret']

server_key_store = json.loads(server_cred_path.read_text())
if 'publickey' not in server_key_store:
    server_key_store['publickey'] = server_key_store['public']
    server_key_store['secretkey'] = server_key_store['secret']


#"ipc://@/home/os2204/.volttron_original/run/vip.socket?publickey=HqKAAZc6s_CNf1Xlmi5V8SYlmjQ09mFvFL0HMwzuiVU&secretkey=LOsjvmfjEQWKqlQdphxMr8incSro9CTsP2Vm_Arvl80&serverkey=hZoDI7McGJG8K7tCnyEJxl0FFIQiXCHxvRh2pylxukI"


#server_public_key = "BkZi1cYswb19qoxXSkb1Cs4b3-7hX8nQ48CZY_WwG1U"
server_public_key = server_key_store['publickey']

#client_creds = json.loads(cred_path.read_text())
#control_conn_store = client_creds


client = ctx.socket(zmq.DEALER)
client.identity = CONTROL_CONNECTION.encode("utf-8")
client.curve_secretkey = decode_key(cred_key_store["secretkey"])
client.curve_publickey = decode_key(cred_key_store["publickey"])
client.curve_serverkey = decode_key(server_public_key)

client.connect(address)

if client.poll():
    msg = client.recv()
    print(f"Received: {msg!r}")
    if msg == b"Hello":
        print("Ironhouse test OK")
    else:
        print(f"What did I get? {msg!r}")
else:
    print("Ironhouse test FAIL")
