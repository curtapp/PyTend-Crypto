from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from tend.crypto import sha256
from tend.crypto.csp import keys, SignerOpts, HashOpts

ALGORITHM = 'ED25519'


@dataclass
class KeyGenOpts(keys.KeyGenOpts):
    algorithm = ALGORITHM
    ephemeral = False


@dataclass
class KeyDerivOpts(keys.KeyDerivOpts):
    algorithm = ALGORITHM
    ephemeral = False


@dataclass
class KeyImportOpts(keys.KeyImportOpts):
    private: bool = True
    algorithm = ALGORITHM
    ephemeral = False


@dataclass
class Sha256SignerOpts(SignerOpts):

    @property
    def hash_options(self) -> HashOpts:
        return sha256.HashOpts()


class Key(keys.Key):
    """ Implementation of `csp.Key` for ed25519 keys
    """

    def __init__(self, raw: bytes | Ed25519PrivateKey | Ed25519PublicKey,
                 opts: KeyGenOpts | KeyImportOpts | KeyDerivOpts):
        if isinstance(raw, bytes):
            if opts.private:
                self._raw = Ed25519PrivateKey.from_private_bytes(raw[:32])
            else:
                self._raw = Ed25519PublicKey.from_public_bytes(raw)
        else:
            self._raw = raw
        self._opts = opts

    @property
    def raw(self) -> Ed25519PrivateKey | Ed25519PublicKey:
        return self._raw

    @property
    def ski(self) -> bytes:
        return sha256.sum(bytes(self.public_key) if self.private else bytes(self))[:20]

    @property
    def opts(self) -> KeyGenOpts | KeyImportOpts | KeyDerivOpts:
        return self._opts

    def __bytes__(self) -> bytes:
        return (self.raw.private_bytes(encoding=serialization.Encoding.Raw,
                                       format=serialization.PrivateFormat.Raw,
                                       encryption_algorithm=serialization.NoEncryption())
                if self.private else self.raw.public_bytes(encoding=serialization.Encoding.Raw,
                                                           format=serialization.PublicFormat.Raw))

    @property
    def symmetric(self) -> bool:
        return False

    @property
    def private(self) -> bool:
        return isinstance(self.raw, Ed25519PrivateKey)

    @property
    def public_key(self) -> 'Key':
        return Key(self._raw.public_key(), KeyGenOpts()) if self.private else self
