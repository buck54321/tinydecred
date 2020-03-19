"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import unittest

from decred import DecredError
from decred.crypto import crypto, rando
from decred.dcr.nets import mainnet
from decred.util.encode import ByteArray


testSeed = ByteArray(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
).b


class TestCrypto(unittest.TestCase):
    def test_encryption(self):
        """
        Test encryption and decryption.
        """
        a = crypto.SecretKey("abc".encode())
        aEnc = a.encrypt(
            b"dprv3n8wmhMhC7p7QuzHn4fYgq2d87hQYAxWH3RJ6pYFrd7LAV71RcBQ"
            b"WrFFmSG3yYWVKrJCbYTBGiniTvKcuuQmi1hA8duKaGM8paYRQNsD1P6"
        )
        b = crypto.SecretKey.rekey("abc".encode(), a.params())
        aUnenc = b.decrypt(aEnc)
        self.assertTrue(a, aUnenc)

    def test_addr_secp_pubkey(self):
        data = [
            (
                "033b26959b2e1b0d88a050b111eeebcf776a38447f7ae5806b53c9b46e07c267ad",
                "DkRKjw7LmGCSzBwaUtjQLfb75Zcx9hH8yGNs3qPSwVzZuUKs7iu2e",
                "e201ee2f37bcc0ba0e93f82322e48333a92b9355",
            ),
            (
                "0389ced3eaee84d5f0d0e166f6cd15f1bf6f429d1d13709393b418a6fb22d8be53",
                "DkRLLaJWkmH75iZGtQYE6FEf16zxeHr6TCAF59tGxhds4MFc2HqUS",
                "5643d59202de158b509544d40b32e85bfaf6243e",
            ),
            (
                "02a14a0023d7d8cbc5d39fa60f7e4dc4d5bf18a7031f52875fbca6bf837f68713f",
                "DkM3hdWuKSSTm7Vq8WZx5f294vcZbPkAQYBDswkjmF1CFuWCRYxTr",
                "c5fa0d15266e055eaf8ec7c4d7a679885266ef0d",
            ),
            (
                "03c3e3d7cde1c453a6283f5802a73d1cb3827cb4b007f58e3a52a36ce189934b6a",
                "DkRLn9vzsjK4ZYgDKy7JVYHKGvpZU5CYGK9H8zF2VCWbpTyVsEf4P",
                "73612f7b7b1ed32ff44dded7a2cf87c206fabf8a",
            ),
            (
                "0254e17b230e782e591a9910794fdbf9943d500a47f2bf8446e1238f84e809bffc",
                "DkM37ymaat9j6oTFii1MZVpXrc4aRLEMHhTZrvrz8QY6BZ2HX843L",
                "a616bc09179e31e6d9e3abfcb16ac2d2baf45141",
            ),
        ]
        for hexKey, addrStr, hash160 in data:
            addr = crypto.AddressSecpPubKey(ByteArray(hexKey), mainnet)
            self.assertEqual(addr.string(), addrStr)
            self.assertEqual(addr.hash160().hex(), hash160)

    def test_addr_pubkey_hash(self):
        pairs = [
            (
                "e201ee2f37bcc0ba0e93f82322e48333a92b9355",
                "DsmZvWuokf5NzFwFfJk5cALZZBZivjkhMSQ",
            ),
            (
                "5643d59202de158b509544d40b32e85bfaf6243e",
                "DsYq2s8mwpM6vXLbjb8unhNmBXFofPzcrrv",
            ),
            (
                "c5fa0d15266e055eaf8ec7c4d7a679885266ef0d",
                "Dsj1iA5PBCU6Nmpe6jqucwfHK17WmSKd3uG",
            ),
            (
                "73612f7b7b1ed32ff44dded7a2cf87c206fabf8a",
                "DsbUyd4DueVNyvfh542kZDXNEGKByUAi1RV",
            ),
            (
                "a616bc09179e31e6d9e3abfcb16ac2d2baf45141",
                "Dsg76ttvZmTFchZ5mWRnAUg6UGfCyrq86ch",
            ),
        ]
        for pubkeyHash, addrStr in pairs:
            pubkeyHashBA = ByteArray(pubkeyHash)
            addr = crypto.AddressPubKeyHash(mainnet.PubKeyHashAddrID, pubkeyHashBA)
            self.assertEqual(addr.string(), addrStr)
            self.assertEqual(addr.scriptAddress(), pubkeyHashBA)
            self.assertEqual(addr.hash160(), pubkeyHashBA)

    def test_addr_script_hash(self):
        pairs = [
            (
                "52fdfc072182654f163f5f0f9a621d729566c74d",
                "Dcf2QjJ1pSnLwthhw1cwE55MVZNQVXDZWQT",
            ),
            (
                "10037c4d7bbb0407d1e2c64981855ad8681d0d86",
                "DcYvG3fPxHDZ5pzW8nj4rcYq5kM9XFxXpUy",
            ),
            (
                "d1e91e00167939cb6694d2c422acd208a0072939",
                "DcrbVYmhm5yX9mw9qdwUVWw6psUhPGrQJsT",
            ),
            (
                "487f6999eb9d18a44784045d87f3c67cf22746e9",
                "Dce4vLzzENaZT7D2Wq5crRZ4VwfYMDMWkD9",
            ),
            (
                "95af5a25367951baa2ff6cd471c483f15fb90bad",
                "Dcm73og7Hn9PigaNu59dHgKnNSP1myCQ39t",
            ),
        ]
        for scriptHash, addrStr in pairs:
            addr = crypto.newAddressScriptHashFromHash(ByteArray(scriptHash), mainnet)
            self.assertEqual(addr.string(), addrStr)

    def test_kdf_params(self):
        salt = rando.newHash()
        auth = ByteArray(32)
        kdf = crypto.KDFParams(salt, auth)
        b = kdf.serialize()
        reKDF = crypto.KDFParams.unblob(b.b)
        self.assertEqual(kdf.kdfFunc, reKDF.kdfFunc)
        self.assertEqual(kdf.hashName, reKDF.hashName)
        self.assertEqual(kdf.salt, reKDF.salt)
        self.assertEqual(kdf.auth, reKDF.auth)
        self.assertEqual(kdf.iterations, reKDF.iterations)

    def test_secret_key(self):
        sk = crypto.SecretKey("pass".encode())
        test = b"testphrase"
        enc = sk.encrypt(test)
        dec = sk.decrypt(enc)
        self.assertEqual(test, dec)

    def test_extended_key(self):
        """
        Test extended key derivation.
        """
        kpriv = crypto.ExtendedKey.new(testSeed)
        kpriv.setNetwork(mainnet)
        self.assertEqual(
            kpriv.key.hex(),
            "f2418d00085be520c6449ddb94b25fe28a1944b5604193bd65f299168796f862",
        )
        kpub = kpriv.neuter()
        self.assertEqual(
            kpub.key.hex(),
            "0317a47499fb2ef0ff8dc6133f577cd44a5f3e53d2835ae15359dbe80c41f70c9b",
        )
        # Neutering again should make no difference.
        kpub2 = kpub.neuter()
        self.assertEqual(
            kpub2.key.hex(),
            "0317a47499fb2ef0ff8dc6133f577cd44a5f3e53d2835ae15359dbe80c41f70c9b",
        )
        kpub_branch0 = kpub.child(0)
        self.assertEqual(
            kpub_branch0.key.hex(),
            "02dfed559fddafdb8f0041cdd25c4f9576f71b0e504ce61837421c8713f74fb33c",
        )
        kpub_branch0_child1 = kpub_branch0.child(1)
        self.assertEqual(
            kpub_branch0_child1.key.hex(),
            "03745417792d529c66980afe36f364bee6f85a967bae117bc4d316b77e7325f50c",
        )
        kpriv_branch0 = kpriv.child(0)
        self.assertEqual(
            kpriv_branch0.key.hex(),
            "6469a8eb3ed6611cc9ee4019d44ec545f3174f756cc41f9867500efdda742dd9",
        )
        kpriv_branch0_child1 = kpriv_branch0.child(1)
        self.assertEqual(
            kpriv_branch0_child1.key.hex(),
            "fb8efe52b3e4f31bc12916cbcbfc0e84ef5ebfbceb7197b8103e8009c3a74328",
        )
        kpriv01_neutered = kpriv_branch0_child1.neuter()
        self.assertEqual(kpriv01_neutered.key.hex(), kpub_branch0_child1.key.hex())

        # fmt: off
        # Incorrect length of network version bytes.
        self.assertRaises(
            DecredError,
            crypto.ExtendedKey,
            # privVer too short.
            ByteArray([0, 0, 0]),
            ByteArray([0, 0, 0, 0]),
            None, None, None, None, None, None, None
        )
        self.assertRaises(
            DecredError,
            crypto.ExtendedKey,
            ByteArray([0, 0, 0, 0]),
            # pubVer too long.
            ByteArray([0, 0, 0, 0, 0]),
            None, None, None, None, None, None, None
        )
        # fmt: on

        # Cannot serialize an empty private key.
        kpriv2 = crypto.ExtendedKey.new(testSeed)
        kpriv2.key.zero()
        self.assertRaises(DecredError, kpriv2.serialize)
