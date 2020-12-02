"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019-2020, The Decred developers
See LICENSE for details

Cryptographic functions.
"""

import hashlib
import hmac

from base58 import b58decode, b58encode
from blake256.blake256 import blake_hash
import nacl.secret

from decred import DecredError
from decred.util import encode
from decred.util.encode import ByteArray, unblobCheck

from . import rando
from .secp256k1.curve import PrivateKey, PublicKey, curve as Curve


BLAKE256_SIZE = 32
RIPEMD160_SIZE = 20
SERIALIZED_KEY_LENGTH = 4 + 1 + 4 + 4 + 32 + 33  # 78 bytes
HARDENED_KEY_START = 2 ** 31
MAX_COIN_TYPE = HARDENED_KEY_START - 1
MAX_ACCOUNT_NUM = HARDENED_KEY_START - 2
RADIX = 58
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MASTER_KEY = b"Bitcoin seed"
MAX_SECRET_INT = (
    115792089237316195423570985008687907852837564279074904382605163141518161494337
)

# ExternalBranch is the child number to use when performing BIP0044 style
# hierarchical deterministic key derivation for the external branch.
EXTERNAL_BRANCH = 0

# InternalBranch is the child number to use when performing BIP0044
# style hierarchical deterministic key derivation for the internal
# branch.
INTERNAL_BRANCH = 1

# STEcdsaSecp256k1 specifies that the signature is an ECDSA signature
# over the secp256k1 elliptic curve.
STEcdsaSecp256k1 = 0

# STEd25519 specifies that the signature is an ECDSA signature over the
# edwards25519 twisted Edwards curve.
STEd25519 = 1

# STSchnorrSecp256k1 specifies that the signature is a Schnorr
# signature over the secp256k1 elliptic curve.
STSchnorrSecp256k1 = 2

# PKFUncompressed indicates the pay-to-pubkey address format is an
# uncompressed public key.
PKFUncompressed = 0

# PKFCompressed indicates the pay-to-pubkey address format is a
# compressed public key.
PKFCompressed = 1


class CrazyKeyError(DecredError):
    """
    Both derived public or private keys rely on treating the left 32-byte
    sequence calculated above (Il) as a 256-bit integer that must be within the
    valid range for a secp256k1 private key.  There is an extremely tiny chance
    (< 1 in 2^127) this condition will not hold, and in that case, a child
    extended key can't be created for this index and the caller should simply
    increment to the next index.
    """

    pass


class ParameterRangeError(DecredError):
    """
    An input parameter is out of the acceptable range.
    """

    pass


class KeyLengthError(DecredError):
    """
    A KeyLengthError indicates a hash input that is of an unexpected length.
    """

    pass


def hmacDigest(key, msg, digestmod=hashlib.sha512):
    """
    Get the hmac keyed hash.

    Args:
        key (byte-like): the key
        msg (byte-like): the message
        digestmod (digest): A hashlib digest type constant.

    Returns:
        str: The secure hash of msg.
    """
    h = hmac.new(key, msg=msg, digestmod=digestmod)
    return h.digest()


def hash160(b):
    """
    A RIPEMD160 hash of the blake256 hash of the input.

    Args:
        b (byte-like): The bytes to hash.

    Returns:
        ByteArray: A 20-byte hash.
    """
    h = hashlib.new("ripemd160")
    h.update(blake_hash(b))
    return ByteArray(h.digest())


def checksum(b):
    """
    A checksum.

    Args:
        b (byte-like): Bytes to obtain a checksum for.

    Returns:
        bytes: A 4-byte checksum.
    """
    return blake_hash(blake_hash(b))[:4]


def sha256ChecksumByte(input):
    """
    This checksum byte is used for the PGP-based mnemonic seed checksum word.

    Args:
        input (byte-like): Bytes to obtain a checksum for.

    Returns:
        byte: The first byte of a double sha256 hash of input.
    """
    v = hashlib.sha256(input).digest()
    return hashlib.sha256(v).digest()[0]


def mac(key, msg):
    """
    SHA256-based message authentication code.

    Args:
        key (byte-like): Authentication key.
        msg (byte-like): Message to hash.

    Returns:
        ByteArray: The authentication hash.
    """
    return ByteArray(hmacDigest(key.bytes(), msg.bytes(), hashlib.sha256))


def egcd(a, b):
    """
    Calculate the extended Euclidean algorithm. ax + by = gcd(a,b)

    Args:
        a (int): An integer.
        b (int): Another integer.

    Returns:
        int: Greatest common denominator.
        int: x coefficient of Bezout's identity.
        int: y coefficient of Bezout's identity.
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modInv(a, m):
    """
    Modular inverse based on https://stackoverflow.com/a/9758173/1124661.
    Raises an exception if impossible.

    Args:
        a (int): An integer.
        m (int): The modulus.

    Returns:
        int: The modular inverse.
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise DecredError("modular inverse does not exist")
    return x % m


def hashH(b):
    """
    The BLAKE256 hash as a ByteArray.

    Args:
        b (byte-like): The thing to hash.

    Returns:
        ByteArray: The hash.
    """
    return ByteArray(blake_hash(b), length=BLAKE256_SIZE)


def b58CheckDecode(s):
    """
    Decode the base-58 encoded address, parsing the version bytes and the pubkey
    hash. An exception is raised if the checksum is invalid or missing.

    Args:
        s (str): The base-58 encoded address.

    Returns:
        ByteArray: Decoded bytes minus the leading version and trailing
            checksum.
        int: The version (leading two) bytes.
    """
    decoded = b58decode(s)
    if len(decoded) < 6:
        raise DecredError("decoded lacking version/checksum")
    version = decoded[:2]
    included_cksum = decoded[len(decoded) - 4 :]
    computed_cksum = checksum(decoded[: len(decoded) - 4])
    if included_cksum != computed_cksum:
        raise DecredError("checksum error")
    payload = ByteArray(decoded[2 : len(decoded) - 4])
    return payload, version


def privKeyFromBytes(pk):
    """
    privKeyFromBytes creates a PrivateKey for the secp256k1 curve based on
    the provided byte-encoding.

    Args:
        pk (ByteArray): The private key bytes.

    Returns:
        secp256k1.Privatekey: The private key structure.
    """
    x, y = Curve.scalarBaseMult(pk.int())
    return PrivateKey(Curve, pk, x, y)


class ExtendedKey:
    """
    ExtendedKey houses all the information needed to support a BIP0044
    hierarchical deterministic extended key.
    """

    def __init__(
        self,
        privVer,
        pubVer,
        key,
        pubKey,
        chainCode,
        parentFP,
        depth,
        childNum,
        isPrivate,
    ):
        """
        Args:
            privVer (byte-like): Network version bytes for extended priv keys.
            pubVer (byte-like): Network version bytes for extended pub keys.
            key (byte-like): The key.
            pubKey (byte-like): Will be the same as `key` for public key. Will
                be generated from key if zero is provided.
            chainCode (byte-like): Chain code for key derivation.
            parentFP (ByteArray): parent key fingerprint.
            depth (int): Key depth.
            childNum (int): Child number.
            isPrivate (bool): Whether the key is a private or public key.
        """
        if len(privVer) != 4 or len(pubVer) != 4:
            msg = "Network version bytes of incorrect lengths {} and {}"
            raise DecredError(msg.format(len(privVer), len(pubVer)))
        self.privVer = ByteArray(privVer)
        self.pubVer = ByteArray(pubVer)
        self.key = ByteArray(key)
        self.pubKey = ByteArray(pubKey)
        if self.pubKey.iszero():
            if isPrivate:
                self.pubKey = Curve.publicKey(self.key.int()).serializeCompressed()
            else:
                self.pubKey = self.key
        self.chainCode = ByteArray(chainCode)
        self.parentFP = ByteArray(parentFP)
        self.depth = depth
        self.childNum = childNum
        self.isPrivate = isPrivate

    @staticmethod
    def new(seed):
        """
        new creates a new crypto.ExtendedKey. Implementation based on dcrd
        hdkeychain newMaster. The ExtendedKey created does not have a network
        specified. The extended key returned from newMaster can be used to
        generate coin-type and account keys in accordance with BIP-0032 and
        BIP-0044.

        Args:
            seed (bytes-like): A random seed from which the extended key is made.

        Returns:
            crypto.ExtendedKey: A master hierarchical deterministic key.
        """
        rando.checkSeedLength(len(seed))

        # First take the HMAC-SHA512 of the master key and the seed data:
        # SHA512 hash is 64 bytes.
        lr = hmacDigest(MASTER_KEY, seed)

        # Split "I" into two 32-byte sequences Il and Ir where:
        #   Il = master secret key
        #   Ir = master chain code
        lrLen = int(len(lr) / 2)
        secretKey = lr[:lrLen]
        chainCode = lr[lrLen:]

        # Ensure the key is usable.
        secretInt = int.from_bytes(secretKey, byteorder="big")
        if secretInt > MAX_SECRET_INT or secretInt <= 0:
            raise KeyLengthError("generated key was outside acceptable range")

        parentFp = bytes.fromhex("00 00 00 00")

        return ExtendedKey(
            privVer=ByteArray([0, 0, 0, 0]),
            pubVer=ByteArray([0, 0, 0, 0]),
            key=secretKey,
            pubKey="",
            chainCode=chainCode,
            parentFP=parentFp,
            depth=0,
            childNum=0,
            isPrivate=True,
        )

    def setNetwork(self, netParams):
        """
        Sets the privVer and pubVer fields. This should be used when deriving
        the coin-type extended keys from the root wallet key.

        Args:
            netParams (module): The network parameters.
        """
        self.privVer = netParams.HDPrivateKeyID
        self.pubVer = netParams.HDPublicKeyID

    def deriveCoinTypeKey(self, netParams):
        """
        First two hardened child derivations in accordance with BIP0044.

        Args:
            netParams (module): The network parameters.

        Returns:
            ExtendedKey: The coin-type key.
        """
        coinType = netParams.SLIP0044CoinType
        if coinType > MAX_COIN_TYPE:
            raise ParameterRangeError(
                "coinType too high. %i > %i" % (coinType, MAX_COIN_TYPE)
            )

        purpose = self.child(44 + HARDENED_KEY_START)

        # Derive the purpose key as a child of the master node.
        coinKey = purpose.child(coinType + HARDENED_KEY_START)
        coinKey.privVer = netParams.HDPrivateKeyID
        coinKey.pubVer = netParams.HDPublicKeyID
        return coinKey

    def child(self, i):
        """
        Child returns a derived child extended key at the given index.  When
        this extended key is a private extended key (as determined by the
        IsPrivate function (TODO: implement IsPrivate)), a private extended key
        will be derived. Otherwise, the derived extended key will also be a
        public extended key.

        When the index is greater than or equal to the HardenedKeyStart
        constant, the derived extended key will be a hardened extended key. It
        is only possible to derive a hardended extended key from a private
        extended key. Consequently, this function will throw an exception if a
        hardened child extended key is requested from a public extended key.

        A hardened extended key is useful since, as previously mentioned, it
        requires a parent private extended key to derive. In other words, normal
        child extended public keys can be derived from a parent public extended
        key (no knowledge of the parent private key) whereas hardened extended
        keys may not be.

        NOTE: There is an extremely small chance (< 1 in 2^127) the specific
        child index does not derive to a usable child. An exception will happen
        if this should occur, and the caller is expected to ignore the invalid
        child and simply increment to the next index.

        There are four scenarios that could happen here:
        1) Private extended key -> Hardened child private extended key
        2) Private extended key -> Non-hardened child private extended key
        3) Public extended key -> Non-hardened child public extended key
        4) Public extended key -> Hardened child public extended key (INVALID!)

        Args:
            i (int): Child number.

        Returns:
            ExtendedKey: The child key.
        """

        # Case #4 is invalid, so error out early.
        # A hardened child extended key may not be created from a public
        # extended key.
        isChildHardened = i >= HARDENED_KEY_START
        if not self.isPrivate and isChildHardened:
            raise ParameterRangeError(
                "cannot generate hardened child from public extended key"
            )

        # The data used to derive the child key depends on whether or not the
        # child is hardened per [BIP32].
        #
        # For hardened children:
        #   0x00 || ser256(parentKey) || ser32(i)
        #
        # For normal children:
        #   serP(parentPubKey) || ser32(i)
        keyLen = 33
        data = ByteArray(bytearray(keyLen + 4))

        if isChildHardened:
            # Case #1.
            # When the child is a hardened child, the key is known to be a
            # private key due to the above early return.  Pad it with a
            # leading zero as required by [BIP32] for deriving the child.
            data[1] = self.key
        else:
            # Case #2 or #3.
            # This is either a public or private extended key, but in
            # either case, the data which is used to derive the child key
            # starts with the secp256k1 compressed public key bytes.
            data[0] = ByteArray(self.pubKey)
        data[keyLen] = ByteArray(i, length=len(data) - keyLen)

        data |= i  # ByteArray will handle the type conversion.

        # Take the HMAC-SHA512 of the current key's chain code and the derived
        # data:
        #   I = HMAC-SHA512(Key = chainCode, Data = data)
        ilr = ByteArray(hmacDigest(self.chainCode.b, data.b, hashlib.sha512))

        # Split "I" into two 32-byte sequences Il and Ir where:
        #   Il = intermediate key used to derive the child
        #   Ir = child chain code
        il = ilr[: len(ilr) // 2]
        childChainCode = ilr[len(ilr) // 2 :]

        # See CrazyKeyError docs for an explanation of this condition.
        if il.int() >= Curve.N or il.iszero():
            raise CrazyKeyError("ExtendedKey.child: generated Il outside valid range")

        # The algorithm used to derive the child key depends on whether or not
        # a private or public child is being derived.
        #
        # For private children:
        #   childKey = parse256(Il) + parentKey
        #
        # For public children:
        #   childKey = serP(point(parse256(Il)) + parentKey)
        isPrivate = False
        if self.isPrivate:
            # Case #1 or #2.
            # Add the parent private key to the intermediate private key to
            # derive the final child key.
            #
            # childKey = parse256(Il) + parenKey
            childKey = ByteArray((self.key.int() + il.int()) % Curve.N)
            isPrivate = True
        else:
            # Case #3.
            # Calculate the corresponding intermediate public key for
            # intermediate private key.

            x, y = Curve.scalarBaseMult(il.int())  # Curve.G as ECPointJacobian
            if x == 0 or y == 0:
                raise ParameterRangeError(
                    "ExtendedKey.child: generated pt outside valid range"
                )
            # Convert the serialized compressed parent public key into X
            # and Y coordinates so it can be added to the intermediate
            # public key.
            pubKey = Curve.parsePubKey(self.key)
            # Add the intermediate public key to the parent public key to
            # derive the final child key.
            #
            # childKey = serP(point(parse256(Il)) + parentKey)
            # childX, childY := curve.Add(pt.x, pt.y, pubKey.X, pubKey.Y)
            childX, childY = Curve.add(x, y, pubKey.x, pubKey.y)
            # pk := secp256k1.PublicKey{Curve: secp256k1.S256(), X: childX, Y: childY}
            # childKey = pk.SerializeCompressed()
            childKey = PublicKey(Curve, childX, childY).serializeCompressed()

        # The fingerprint of the parent for the derived child is the first 4
        # bytes of the RIPEMD160(BLAKE256(parentPubKey)).
        parentFP = hash160(self.pubKey.b)[:4]

        return ExtendedKey(
            privVer=self.privVer,
            pubVer=self.pubVer,
            key=childKey,
            pubKey="",
            chainCode=childChainCode,
            parentFP=parentFP,
            depth=self.depth + 1,
            childNum=i,
            isPrivate=isPrivate,
        )

    def deriveAccountKey(self, acct):
        """
        deriveAccountKey derives the extended key for an account according to
        the hierarchy described by BIP0044 given the master node.

        In particular this is the hierarchical deterministic extended key path:
          m/44'/<coin type>'/<account>'

        Args:
            account (int): Account number.

        Returns:
            ExtendedKey: Account key.
        """
        # Enforce maximum account number.
        if acct > MAX_ACCOUNT_NUM:
            raise ParameterRangeError(
                "deriveAccountKey: account number greater than MAX_ACCOUNT_NUM"
            )

        # Derive the account key as a child of the coin type key.
        return self.child(acct + HARDENED_KEY_START)

    def neuter(self):
        """
        neuter returns a new extended public key from this extended private key.
        The same extended key will be returned unaltered if it is already an
        extended public key.

        As the name implies, an extended public key does not have access to the
        private key, so it is not capable of signing transactions or deriving
        child extended private keys. However, it is capable of deriving further
        child extended public keys.

        Returns:
            ExtendedKey: The public extended key.
        """
        # Already an extended public key.
        if not self.isPrivate:
            return self

        # Convert it to an extended public key. The key for the new extended
        # key will simply be the pubkey of the current extended private key.
        #
        # This is the function N((k,c)) -> (K, c) from [BIP32].
        return ExtendedKey(
            privVer=self.privVer,
            pubVer=self.pubVer,
            key=self.pubKey,
            pubKey=self.pubKey,
            chainCode=self.chainCode,
            parentFP=self.parentFP,
            depth=self.depth,
            childNum=self.childNum,
            isPrivate=False,
        )

    def serialize(self):
        """
        Return the extended key in serialized form.

        Returns:
            ByteArray: The serialized extended key.
        """
        if self.key.iszero():
            raise DecredError("unexpected zero key")

        childNumBytes = ByteArray(self.childNum, length=4)
        depthByte = ByteArray(self.depth % 256, length=1)

        # The serialized format is:
        #   version (4) || depth (1) || parent fingerprint (4)) ||
        #   child num (4) || chain code (32) || key data (33) || checksum (4)
        serializedBytes = ByteArray(
            bytearray(0)
        )  # length serializedKeyLen + 4 after appending
        if self.isPrivate:
            serializedBytes += self.privVer
        else:
            serializedBytes += self.pubVer

        serializedBytes += depthByte
        serializedBytes += self.parentFP
        serializedBytes += childNumBytes
        serializedBytes += self.chainCode
        if self.isPrivate:
            serializedBytes += bytearray(1)
            serializedBytes += self.key
        else:
            serializedBytes += self.pubKey

        checkSum = checksum(serializedBytes.b)[:4]
        serializedBytes += checkSum
        return serializedBytes

    def string(self):
        """
        string returns the extended key as a base58-encoded string. See
        `decodeExtendedKey` for decoding.

        Returns:
            str: The encoded extended key.
        """
        return b58encode(self.serialize().bytes()).decode()

    def privateKey(self):
        """
        A PrivateKey structure that can be used for signatures.

        Returns:
            secp256k1.PrivateKey: The private key structure.
        """
        return privKeyFromBytes(self.key)

    def publicKey(self):
        """
        A PublicKey structure of the pubKey.

        Returns:
            secp256k1.PublicKey: The public key structure.
        """
        return Curve.parsePubKey(self.pubKey)


def decodeExtendedKey(netParams, cryptoKey, key):
    """
    Decode an base58 ExtendedKey using the passphrase and network parameters.

    Args:
        netParams (module): The network parameters.
        cryptoKey (ByteAray): The encryption key.
        key (str): Base-58 encoded extended key.

    Returns:
        ExtendedKey: The decoded key.
    """
    return deserializeExtendedKey(decrypt(cryptoKey, key),netParams)


def deserializeExtendedKey(serialized, netParams):
    serialized_len = len(serialized)
    if serialized_len != SERIALIZED_KEY_LENGTH + 4:
        raise DecredError(f"decoded private key is wrong length: {serialized_len}")

    # The serialized format is:
    #   version (4) || depth (1) || parent fingerprint (4)) ||
    #   child num (4) || chain code (32) || key data (33) || checksum (4)

    # Split the payload and checksum up and ensure the checksum matches.
    payload = serialized[: serialized_len - 4]
    included_cksum = serialized[serialized_len - 4 :]
    computed_cksum = checksum(payload.b)[:4]
    if included_cksum != computed_cksum:
        raise DecredError("wrong checksum")

    # Ensure the version encoded in the payload matches the provided network.
    privVersion = netParams.HDPrivateKeyID
    pubVersion = netParams.HDPublicKeyID
    version = payload[:4]
    if version not in (privVersion, pubVersion):
        raise DecredError(f"Unknown versions {privVersion} {pubVersion} {version}")

    # Deserialize the remaining payload fields.
    depth = payload[4:5].int()
    parentFP = payload[5:9]
    childNum = payload[9:13].int()
    chainCode = payload[13:45]
    keyData = payload[45:78]

    # The key data is a private key if it starts with 0x00. Serialized
    # compressed pubkeys either start with 0x02 or 0x03.
    isPrivate = keyData[0] == 0x00
    if isPrivate:
        # Ensure the private key is valid.  It must be within the range
        # of the order of the secp256k1 curve and not be 0.
        keyData = keyData[1:]
        # if keyNum.Cmp(secp256k1.S256().N) >= 0 || keyNum.Sign() == 0 {
        if (keyData >= Curve.N) or keyData.iszero():
            raise DecredError("unusable key")
        # Ensure the public key parses correctly and is actually on the
        # secp256k1 curve.
        Curve.publicKey(keyData.int())

    return ExtendedKey(
        privVer=privVersion,
        pubVer=pubVersion,
        key=keyData,
        pubKey="",
        chainCode=chainCode,
        parentFP=parentFP,
        depth=depth,
        childNum=childNum,
        isPrivate=isPrivate,
    )


DEFAULT_KDF_PARAMS = {
    "func": "pbkdf2_hmac",
    "hash_name": "sha512",
    "iterations": 100000,
}


def defaultKDFParams():
    """
    Default parameters for the key derivation function.

    Returns:
        str: hmac function name.
        str: hmac hash type name.
        int: Number of iterations.
    """
    d = DEFAULT_KDF_PARAMS
    return d["func"], d["hash_name"], d["iterations"]


class KDFParams:
    """
    Parameters for the key derivation function, including the function used.
    As of now, the KDF parameters must yield a 64-byte key.

    Args:
        salt (ByteArray): A salt.
        auth (ByteArray): An authentication hash.
    """

    def __init__(self, salt, auth=b""):
        self.salt = salt
        func, hn, its = defaultKDFParams()
        self.kdfFunc = func
        self.hashName = hn
        self.iterations = its
        self.auth = auth

    @staticmethod
    def blob(params):
        """Satisfies the encode.Blobber API"""
        return params.baseParams().addData(params.auth).b

    @staticmethod
    def unblob(b):
        """Satisfies the encode.Blobber API"""
        ver, d = encode.decodeBlob(b)
        unblobCheck("KDFParams", ver, len(d), {0: 5})

        params = KDFParams(salt=ByteArray(d[2]), auth=ByteArray(d[4]))

        params.kdfFunc = d[0].decode("utf-8")
        params.hashName = d[1].decode("utf-8")
        params.iterations = encode.intFromBytes(d[3])

        return params

    def baseParams(self):
        """
        Serializes all the parameters except the authentication code.

        Returns:
            BuildyBytes: The serialized parameters.
        """
        return (
            encode.BuildyBytes(0)
            .addData(self.kdfFunc.encode("utf-8"))
            .addData(self.hashName.encode("utf-8"))
            .addData(self.salt)
            .addData(self.iterations)
        )

    def serialize(self):
        """
        Serialize the KDFParams.

        Returns:
            ByteArray: The serialized KDFParams.
        """
        return ByteArray(KDFParams.blob(self))


class SecretKey:
    """
    SecretKey is a password-derived key that can be used for encryption and
    decryption.
    """

    def __init__(self, pw=None):
        """
        Args:
            pw (byte-like): A password that deterministically generates the key.
        """
        super().__init__()
        if not pw:
            self.key = None
            self.keyParams = None
            return
        # If a password was provided, create a new set of key parameters and an
        # authentication code.
        salt = rando.newKey()
        _, hashName, iterations = defaultKDFParams()
        b = ByteArray(
            hashlib.pbkdf2_hmac(hashName, bytes(pw), salt.bytes(), iterations)
        )
        self.key = b[:32]
        self.keyParams = KDFParams(salt)
        authKey = b[32:].bytes()
        authMsg = self.keyParams.baseParams().bytes()
        self.keyParams.auth = ByteArray(
            hashlib.blake2b(authMsg, digest_size=32, key=authKey).digest()
        )

    def params(self):
        """
        The key params can be stored in plain text. They must be provided to
        `rekey` to regenerate a key.

        Returns:
            KDFParams: The hash parameters and salt used to generate the key.
        """
        return self.keyParams

    def encrypt(self, thing):
        """
        Encrypt the input using the key.

        Args:
            thing (byte-like): The thing to encrypt.

        Returns:
            ByteArray: The thing, encrypted.
        """
        return ByteArray(encrypt(self.key, thing))

    def decrypt(self, thing):
        """
        Decrypt the input using the key.

        Args:
            thing (byte-like): The thing to decrypt.

        Returns:
            ByteArray: The thing, decrypted.
        """
        return ByteArray(decrypt(self.key, thing))

    @staticmethod
    def rekey(pw, kp):
        """
        Regenerate a key using its origin key parameters, as returned by
        `params`.

        Args:
            pw (bytes-like): The key password.
            kp (KDFParams): The key parameters from the original generation
                of the key being regenerated.

        Returns:
            SecretKey: The regenerated key.
        """
        sk = SecretKey()
        func = kp.kdfFunc
        if func != "pbkdf2_hmac":
            raise DecredError("unknown key derivation function")
        b = ByteArray(
            hashlib.pbkdf2_hmac(kp.hashName, bytes(pw), bytes(kp.salt), kp.iterations)
        )
        # Get the authentication message and key create the MAC tag to compare
        # with the included key parameters.
        authKey = b[32:].bytes()
        authMsg = kp.baseParams().bytes()
        auth = hashlib.blake2b(authMsg, digest_size=32, key=authKey).digest()
        if auth != kp.auth:
            raise DecredError("rekey auth check failed")

        sk.key = b[:32]
        sk.keyParams = kp
        return sk


def encrypt(key, thing):
    """
    Encrypt the thing with the key.

    Args:
        key (ByteArray or bytes-like): The key.
        thing (ByteArray or bytes-like): The plaintext.

    Returns:
        ByteArray: The ciphertext.
    """
    # This is your safe, you can use it to encrypt or decrypt messages
    box = nacl.secret.SecretBox(bytes(key))

    # Encrypt our message, it will be exactly 40 bytes longer than the
    # original message as it stores authentication information and the
    # nonce alongside it.
    encrypted = box.encrypt(bytes(thing))

    if len(encrypted) != len(thing) + box.NONCE_SIZE + box.MACBYTES:  # nocover
        raise DecredError("wrong encrypted length %d" % len(encrypted))

    return ByteArray(encrypted)


def decrypt(key, thing):
    """
    Decrypt the thing with the key.

    Args:
        key (ByteArray or bytes-like): The key.
        thing (ByteArray or bytes-like): The ciphertext.

    Returns:
        ByteArray: The decoded plaintext.
    """
    return ByteArray(nacl.secret.SecretBox(bytes(key)).decrypt(bytes(thing)))
