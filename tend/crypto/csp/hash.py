from abc import ABC, abstractmethod
from typing import Callable

from tend.crypto.csp.opts import HashOpts

HashFunc = Callable[[bytes], bytes]


class Hasher(ABC):
    """ Hasher interface
    """

    def __init__(self, opts: HashOpts):
        self.__opts = opts

    @property
    def opts(self) -> HashOpts:
        """ Options used during creation
        """
        return self.__opts

    @property
    @abstractmethod
    def size(self) -> int:
        """ Hash size in bytes
        """

    @property
    @abstractmethod
    def block_size(self) -> int:
        """ Max data block size
        """

    @abstractmethod
    def reset(self):
        """ Reset internal hasher state.
        """

    @abstractmethod
    def write(self, block: bytes) -> int:
        """ Sends data block to hash.
        """

    @abstractmethod
    def sum(self, prefix: bytes = None) -> bytes:
        """ Returns current hash with prefix if present. It does not reset hasher.
        """

    @classmethod
    def digest(cls,  block: bytes, opts: HashOpts = None, prefix: bytes = None, ) -> bytes:
        """ Sends data block to hash.
        """
        hasher = cls(opts)
        hasher.write(block)
        return hasher.sum(prefix)


