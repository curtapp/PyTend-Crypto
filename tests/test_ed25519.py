import base64

import pytest

from tend.crypto import ed25519, sha256
from tend.crypto.csp import CSProvider


@pytest.fixture
def csp():
    csp = CSProvider()
    yield csp


def test_key_short(csp: CSProvider):
    key = csp.key_gen(ed25519.KeyGenOpts())
    key1 = csp.key_import(bytes(key), ed25519.KeyImportOpts())
    pub = key.public_key
    assert key.private
    assert not pub.private
    assert not key.symmetric
    assert bytes(key) == bytes(key1)
    assert bytes(key.public_key) == bytes(key1.public_key)
    digest = csp.hash('Hello, world!'.encode('utf8'), sha256.HashOpts())
    signature = csp.sign(key, digest, ed25519.Sha256SignerOpts())
    assert csp.verify(pub, signature, digest, ed25519.Sha256SignerOpts())


def test_key_fixtered(csp: CSProvider):
    address = 'C467D91B9C4421887262E5EC3568C2410F5C3ED7'
    b64pub = b'UeT+k7RxEsLDv/bKx/1uAYyhyVrWt9Mumht3Obik0FY='
    b64key = b'57XufdqH4CCa68/hqBkJMQSttsoy5mMUxvICAflj46JR5P6TtHESwsO/9srH/W4BjKHJWta30y6aG3c5uKTQVg=='
    key = csp.key_import(base64.b64decode(b64key), ed25519.KeyImportOpts(private=True))
    pub = csp.key_import(base64.b64decode(b64pub), ed25519.KeyImportOpts(private=False))
    assert key.private
    assert not pub.private
    assert bytes(key.public_key) == bytes(pub)
    assert base64.b64encode(bytes(key)+bytes(key.public_key)) == b64key
    assert base64.b64encode(bytes(key.public_key)) == b64pub
    assert key.ski.hex().upper() == address
