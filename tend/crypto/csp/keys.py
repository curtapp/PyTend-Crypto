from abc import ABC, abstractmethod


class KeyOpts(ABC):
    """ Key options interface
     """

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """ String ID of key algorithm
        """

    @property
    @abstractmethod
    def ephemeral(self) -> bool:
        """ True if key is ephemeral
        """


class KeyDerivOpts(KeyOpts, ABC):
    """ Derive key options interface
    """


class KeyGenOpts(KeyOpts, ABC):
    """ Generate key options interface
    """


class KeyImportOpts(KeyOpts, ABC):
    """ Import key options interface
    """


class Key:
    """ Key interface
    """

    @property
    @abstractmethod
    def raw(self):
        """ Raw representation of key
        """

    @property
    @abstractmethod
    def ski(self) -> bytes:
        """ Key SKI
        """

    @property
    @abstractmethod
    def opts(self) -> KeyOpts:
        """ Options used during creation
        """

    @abstractmethod
    def __bytes__(self) -> bytes:
        """ Bytes representation """

    @property
    @abstractmethod
    def symmetric(self) -> bool:
        """ True if key is symmetric
        """

    @property
    @abstractmethod
    def private(self) -> bool:
        """ True if key is private
        """

    @property
    @abstractmethod
    def public_key(self) -> 'Key':
        """ Returns public key
        """
