from tend.crypto import ed25519, sha256

from .hash import *
from .keys import *


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


class KeyStore:
    """ Base class of key store
    """

    def __init__(self):
        self._keys = dict()

    @property
    def read_only(self) -> bool:
        """ True if keystore read-only
        """
        return True

    def get_key(self, ski: bytes | str) -> Key:
        """ Gets key by SKI.
        """
        ski = ski if isinstance(ski, bytes) else bytes.fromhex(ski)
        return self._keys[ski]

    def store_key(self, key: Key):
        """ Saves key.
        """
        self._keys[key.ski] = key


class Provider:
    """ Crypto service provider
    """

    def __init__(self, key_store: KeyStore = None):
        self._key_store = key_store or KeyStore()

    def key_gen(self, opts: KeyGenOpts) -> Key:
        """ Generates key  with use `opts`.
        """
        match opts.algorithm:
            case ed25519.ALGORITHM:
                return ed25519.Key(ed25519.Ed25519PrivateKey.generate(), opts)
        raise NotImplementedError(f'`key_gen` with option {opts.__class__.__qualname__} not yet implemented')

    def key_deriv(self, src: Key, opts: KeyDerivOpts) -> Key:
        """ Derives key from `src` with use `opts`.
        """
        raise NotImplementedError(f'`key_deriv` with option {opts.__class__.__qualname__} not yet implemented')

    def key_import(self, raw, opts: KeyImportOpts = None) -> Key:
        """ Imports key from `raw` representation
        """
        if opts:
            match opts.algorithm:
                case ed25519.ALGORITHM:
                    return ed25519.Key(raw, opts)
            raise NotImplementedError(f'`key_import` with option {opts.__class__.__qualname__} not yet implemented')
        else:
            if isinstance(raw, ed25519.Ed25519PrivateKey):
                return ed25519.Key(raw, ed25519.KeyImportOpts())
            raise NotImplementedError(f'`key_import` from {raw.__class__.__qualname__} not yet implemented')

    def get_key(self, ski: bytes | str) -> Key:
        """ Gets key by SKI.
        """
        return self._key_store.get_key(ski)

    def hash(self, msg: bytes, opts: HashOpts) -> bytes:
        """ Hashes message with `opts`.
        """
        match opts.algorithm:
            case sha256.ALGORITHM:
                hasher = sha256.Hash()
                hasher.write(msg)
                return hasher.sum()
        raise NotImplementedError(f'`hash` with option {opts.__class__.__qualname__} not yet implemented')

    def get_hash(self, opts: HashOpts) -> 'Hasher':
        """ Returns hasher for `opts`.
        """
        match opts.algorithm:
            case sha256.ALGORITHM:
                return sha256.Hash()
        raise NotImplementedError(f'`get_hash` with option {opts.__class__.__qualname__} not yet implemented')

    def sign(self, key: Key, digest: bytes, opts: SignerOpts) -> bytes:
        """ Signs digest using `key` and `opts` """
        match key.opts.algorithm:
            case ed25519.ALGORITHM:
                raw = key.raw  # type:ed25519.Ed25519PrivateKey
                return raw.sign(self.hash(digest, opts.hash_options))
            case _:
                raise NotImplementedError(f'`sign` for key {key.__class__.__qualname__} not yet implemented')

    def verify(self, pub: Key, signature: bytes, digest: bytes, opts: SignerOpts) -> bool:
        """ Verifies signature against `key` and `digest` with use `opts` """
        match pub.opts.algorithm:
            case ed25519.ALGORITHM:
                raw = pub.public_key.raw  # type:ed25519.Ed25519PublicKey
                try:
                    raw.verify(signature, self.hash(digest, opts.hash_options))
                    return True
                except Exception:
                    return False
            case _:
                raise NotImplementedError(f'`verify` for key {pub.__class__.__qualname__} not yet implemented')

    def encrypt(self, key: Key, plaintext: bytes, opts: EncrypterOpts) -> bytes:
        """ Encrypts plaintext using `key` and `opts` """
        raise NotImplementedError(f'`encrypt` with option {opts.__class__.__qualname__} not yet implemented')

    def decrypt(self, key: Key, ciphertext: bytes, opts: DecrypterOpts) -> bytes:
        """ Decrypt decrypts ciphertext using `key`  and `opts` """
        raise NotImplementedError(f'`decrypt` with option {opts.__class__.__qualname__} not yet implemented')

