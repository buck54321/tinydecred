#!/usr/bin/env python3
"""
Copyright (c) 2020, The Decred developers

This example script will dump all funds located in an xpriv to a specified address.
"""
import os
from urllib.parse import urlunsplit

from base58 import b58decode, b58encode
from decred import DecredError
from decred.crypto import crypto
from decred.crypto.secp256k1.curve import curve as Curve
from decred.dcr import account, addrlib, nets, rpc, txscript
from decred.dcr.wire import msgtx, wire
from decred.util import helpers
from decred.util.encode import ByteArray


SERIALIZED_KEY_LENGTH = 4 + 1 + 4 + 4 + 32 + 33  # 78 bytes
INTERNAL = 0
EXTERNAL = 1
FEE_RATE = 10000
GAP_LIMIT = 20


def cfg(isTestnet):
    dcrdCfgDir = helpers.appDataDir("dcrd")
    cfgPath = os.path.join(dcrdCfgDir, "dcrd.conf")
    if not os.path.isfile(cfgPath):
        return None
    cfg = helpers.readINI(cfgPath, ["rpcuser", "rpcpass", "rpccert"])
    assert "rpcuser" in cfg
    assert "rpcpass" in cfg
    if "rpccert" not in cfg:
        cfg["rpccert"] = os.path.join(dcrdCfgDir, "rpc.cert")
    if "rpclisten" not in cfg:
        cfg["rpclisten"] = "localhost:9109"
    if isTestnet:
        cfg["rpclisten"] = "localhost:19109"
    return cfg


def decodeExtendedKey(netParams, key):
    """
    Decode an base58 ExtendedKey using the passphrase and network parameters.

    Args:
        netParams (module): The network parameters.
        key (str): Base-58 encoded extended key.

    Returns:
        ExtendedKey: The decoded key.
    """
    decoded = ByteArray(b58decode(key))
    decoded_len = len(decoded)
    if decoded_len != SERIALIZED_KEY_LENGTH + 4:
        raise DecredError(f"decoded private key is wrong length: {decoded_len}")

    # The serialized format is:
    #   version (4) || depth (1) || parent fingerprint (4)) ||
    #   child num (4) || chain code (32) || key data (33) || checksum (4)

    # Split the payload and checksum up and ensure the checksum matches.
    payload = decoded[: decoded_len - 4]
    included_cksum = decoded[decoded_len - 4 :]
    computed_cksum = crypto.checksum(payload.b)[:4]
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

    return crypto.ExtendedKey(
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


def getUTXOs(node, key, net):
    """Get a list of all unspent utxo paying to the branch within the gap limit."""
    idx, txGap = 0, 0
    utxos = []
    while txGap < GAP_LIMIT:
        addr = ""
        try:
            addr = addrlib.deriveChildAddress(key, idx, net)
        except Exception:
            # Very small chance of a bad address.
            pass
        try:
            res = node.searchRawTransactions(addr, verbose=True)
            for rawTx in res:
                for vout in rawTx.vout:
                    try:
                        if addr in vout.scriptPubKey.addresses:
                            privKey = key.child(idx)
                            # This should throw if the output is spent.
                            out = node.getTxOut(rawTx.txHash, vout.n)
                            utxo = {
                                "privKey": crypto.privKeyFromBytes(privKey.key),
                                "hash": rawTx.txHash,
                                "n": vout.n,
                                "value": out.value,
                                "script": out.scriptPubKey.script,
                            }
                            utxos.append(utxo)
                    except Exception:
                        pass
            # txs found, reset no txs gap
            txGap = 0
        except Exception:
            # No txs found.
            txGap += 1
        idx += 1
    return utxos


def signUTXOs(node, utxos, sendToAddr, totalValue, net):
    """
    Create one trasaction spending all the outputs to the passed address and sign the
    inputs.
    """
    payToScript = txscript.payToAddrScript(sendToAddr)
    output = msgtx.TxOut(value=0, version=0, pkScript=payToScript)
    inputs = []
    for utxo in utxos:
        opCodeClass = txscript.getP2PKHOpCode(utxo["script"])
        tree = (
            wire.TxTreeRegular
            if opCodeClass == txscript.opNonstake
            else wire.TxTreeStake
        )
        op = msgtx.OutPoint(txHash=utxo["hash"], idx=utxo["n"], tree=tree)
        txIn = msgtx.TxIn(previousOutPoint=op, valueIn=int(utxo["value"] * 1e8))
        inputs.append(txIn)

    newTx = msgtx.MsgTx(
        serType=wire.TxSerializeFull,
        version=txscript.generatedTxVersion,
        txIn=inputs,
        txOut=[output],
        lockTime=0,
        expiry=0,
        cachedHash=None,
    )
    fee = txscript.calcMinRequiredTxRelayFee(FEE_RATE, newTx.serializeSize())
    if fee > totalValue:
        raise DecredError("Not enough funds to cover the transaction fee.")

    newTx.txOut[0].value = totalValue - int(fee)

    for idx, utxo in enumerate(utxos):
        signatureScript, _, _, _ = txscript.sign(
            net,
            newTx,
            idx,
            utxo["script"],
            txscript.SigHashAll,
            account.KeySource(priv=lambda _: utxo["privKey"], internal=None),
            crypto.STEcdsaSecp256k1,
        )
        newTx.txIn[idx].signatureScript = signatureScript

    return newTx


def main():
    net = None
    isTestnet = False
    tString = ""
    netStr = input("Is this mainnet or testnet?\n")
    if netStr in ["testnet", "test", "t"]:
        net = nets.testnet
        isTestnet = True
        tString = "t"
    elif netStr in ["mainnet", "main", "m"]:
        net = nets.mainnet
    else:
        raise DecredError("Unknown network entered.")

    xprivStr = input("Enter xpriv: ")
    xpriv = decodeExtendedKey(net, xprivStr)
    # Double check that we can reproduce the xpriv.
    if b58encode(xpriv.serialize().b).decode() != xprivStr:
        raise DecredError("unknown xpriv parsing error")

    internal = xpriv.child(INTERNAL)
    external = xpriv.child(EXTERNAL)

    dcrdConfig = cfg(isTestnet)
    node = rpc.Client(
        urlunsplit(("https", dcrdConfig["rpclisten"], "/", "", "")),
        dcrdConfig["rpcuser"],
        dcrdConfig["rpcpass"],
        dcrdConfig["rpccert"],
    )

    utxos = getUTXOs(node, internal, net) + getUTXOs(node, external, net)
    totalValue = sum((utxo["value"] for utxo in utxos))

    if totalValue == 0:
        print("No funds found to send.")
        return

    print(f"Found {len(utxos)} outputs totalling {totalValue} {tString}dcr.\n")

    sendToAddrStr = input("Input address to send funds: ")
    # Will throw if bad addr.
    sendToAddr = addrlib.decodeAddress(sendToAddrStr, net)
    signedTx = signUTXOs(node, utxos, sendToAddr, int(totalValue * 1e8), net)

    print(f"Got the raw hex: {signedTx.serialize().hex()}")
    print(f"{repr(signedTx)}\n")
    doIt = input(f"Really send funds to {sendToAddrStr}?\n")
    if doIt in ("yes", "y"):
        txid = node.sendRawTransaction(signedTx)
        print(f"Sent transaction: {reversed(txid).hex()}")
    else:
        print("Aborted.")


main()
