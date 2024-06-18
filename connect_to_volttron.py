import zmq.green as zmq
from zmq.utils import z85
import zmq.auth
import base64
import binascii


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

address = 'ipc://@/home/os2204/.volttron_redo/run/vip.socket'
#address = 'tcp://127.0.0.1:22916'

server_key_store = {
    "public": "GaN29vtS9Eowfkz9_8skI01ePdJLXhl1VrZmkE2zFCI",
    "secret": "ILvSu5p4IYL0vXxCfmajchTL2rbRgCRg4IZ1q4FXmoM"
}

"ipc://@/home/os2204/.volttron_redo/run/vip.socket?publickey=HqKAAZc6s_CNf1Xlmi5V8SYlmjQ09mFvFL0HMwzuiVU&secretkey=LOsjvmfjEQWKqlQdphxMr8incSro9CTsP2Vm_Arvl80&serverkey=BkZi1cYswb19qoxXSkb1Cs4b3-7hX8nQ48CZY_WwG1U"


#server_public_key = "BkZi1cYswb19qoxXSkb1Cs4b3-7hX8nQ48CZY_WwG1U"
server_public_key = "V9E9fKdD4vPydbnm4ugQLbddn6rg_Iht504ucJZEZn0"

control_conn_store = {
    "identity": "control.connection",
    "publickey": "HqKAAZc6s_CNf1Xlmi5V8SYlmjQ09mFvFL0HMwzuiVU",
    "secretkey": "LOsjvmfjEQWKqlQdphxMr8incSro9CTsP2Vm_Arvl80"
}

client = ctx.socket(zmq.DEALER)
client.curve_secretkey = decode_key(control_conn_store["secretkey"])
client.curve_publickey = decode_key(control_conn_store["publickey"])
client.curve_serverkey = decode_key(server_public_key)

client.connect(address)

if client.poll(1000):
    msg = client.recv()
    if msg == b"Hello":
        print("Ironhouse test OK")
    else:
        print(f"What did I get? {msg!r}")
else:
    print("Ironhouse test FAIL")
