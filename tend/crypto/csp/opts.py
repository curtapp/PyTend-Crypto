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


class HashOpts(ABC):
    """ Hasher options interface """

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """ String ID of hash algorithm
        """


class SignerOpts(ABC):
    """ Signer options interface
    """

    @property
    @abstractmethod
    def hash_options(self) -> HashOpts:
        """ Returns hash options of signer
        """


class EncrypterOpts(ABC):
    """ Encrypter options interface
    """


class DecrypterOpts(ABC):
    """ Decrypter options interface
    """