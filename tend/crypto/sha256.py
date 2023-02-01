import hashlib
from dataclasses import dataclass

from tend.crypto.csp import opts, hash

ALGORITHM = 'SHA256'


@dataclass
class HashOpts(opts.HashOpts):
    algorithm = ALGORITHM


class Hash(hash.Hasher):
    """ SHA256 Hasher
    """

    def __init__(self, *args):
        self._hasher = hashlib.new('sha256')
        super().__init__(HashOpts())

    @property
    def size(self) -> int:
        return self._hasher.digest_size

    @property
    def block_size(self) -> int:
        return self._hasher.block_size

    def reset(self):
        self._hasher = hashlib.sha256()

    def write(self, block: bytes) -> int:
        self._hasher.update(block)
        return len(block)

    def sum(self, prefix: bytes = None) -> bytes:
        prefix = prefix or b''
        return prefix + self._hasher.digest()


def sum(msg: bytes, prefix: bytes = None):
    """ Hashes `msg` with sha256
    """
    hasher = Hash()
    hasher.write(msg)
    return hasher.sum(prefix)
