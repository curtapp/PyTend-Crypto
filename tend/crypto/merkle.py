from tend.crypto.csp.hash import BlockHasher
from tend.crypto.csp.opts import HashOpts
from tend.crypto.csp import CSProvider


class MerkleTree(BlockHasher):
    """ Merkle tree
    """

    def __int__(self, csp: CSProvider, opts: HashOpts):
        self._leafs = list()
        self._hasher_factory = lambda: csp.get_hash(opts)
        self._root_hasher = self._hasher_factory()

    @property
    def size(self) -> int:
        """ Digest size of used hasher """
        return self._root_hasher.size

    @property
    def block_size(self) -> int:
        """ Internal block size of used hasher """
        return self._root_hasher.block_size

    def write_data(self, data: bytes) -> bytes:
        """ Hashes `data` and writes to the tree's leaf a result digest
        """

    def write_hash(self, block: bytes):
        """ Writes to tree ready leaf digest
        """

    def sum(self, prefix: bytes = None) -> bytes:
        """ Returns root digest
        """

    def reset(self):
        """ Clears hasher state """
        self._root_hasher = self._hasher_factory()

    def clear(self):
        """ Clears tree state """
        self._leafs.clear()
        self.reset()
