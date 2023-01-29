import typing as t
from abc import ABC, abstractmethod

HashFunc = t.Callable[[bytes], bytes]


class HashOpts(ABC):
    """ Hasher options interface """

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """ String ID of hash algorithm
        """


class Hasher(ABC):
    """ Hasher interface
    """

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