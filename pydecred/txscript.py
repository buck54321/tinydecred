"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details

Based on dcrd txscript.
"""
import unittest
from tinydecred.crypto.bytearray import ByteArray
from tinydecred.pydecred.wire import wire, msgtx # A couple of usefule serialization functions.
from tinydecred.crypto import opcode, crypto
from tinydecred.crypto.secp256k1.curve import curve as Curve

HASH_SIZE = 32
SHA256_SIZE = 32
BLAKE256_SIZE = 32

NonStandardTy      = 0  # None of the recognized forms.
PubKeyTy           = 1  # Pay pubkey.
PubKeyHashTy       = 2  # Pay pubkey hash.
ScriptHashTy       = 3  # Pay to script hash.
MultiSigTy         = 4  # Multi signature.
NullDataTy         = 5  # Empty data-only (provably prunable).
StakeSubmissionTy  = 6  # Stake submission.
StakeGenTy         = 7  # Stake generation
StakeRevocationTy  = 8  # Stake revocation.
StakeSubChangeTy   = 9  # Change for stake submission tx.
PubkeyAltTy        = 10 # Alternative signature pubkey.
PubkeyHashAltTy    = 11 # Alternative signature pubkey hash.

# DefaultScriptVersion is the default scripting language version
# representing extended Decred script.
DefaultScriptVersion = 0

# Hash type bits from the end of a signature.
SigHashAll          = 0x1
SigHashNone         = 0x2
SigHashSingle       = 0x3
SigHashAnyOneCanPay = 0x80

# sigHashMask defines the number of bits of the hash type which is used
# to identify which outputs are signed.
sigHashMask = 0x1f

# SigHashSerializePrefix indicates the serialization does not include
# any witness data.
SigHashSerializePrefix = 1

# SigHashSerializeWitness indicates the serialization only contains
# witness data.
SigHashSerializeWitness = 3

# from chaincfg
SigHashOptimization = False

varIntSerializeSize = wire.varIntSerializeSize

# These are the constants specified for maximums in individual scripts.
MaxOpsPerScript       = 255  # Max number of non-push operations.
MaxPubKeysPerMultiSig = 20   # Multisig can't have more sigs than this.
MaxScriptElementSize  = 2048 # Max bytes pushable to the stack.

# A couple of hashing functions from the crypto module.
mac = crypto.mac
hashH = crypto.hashH

class Signature:
    """
    The Signature class represents an ECDSA-algorithm signature. 
    """
    def __init__(self, r, s):
        self.r = r
        self.s = s
    def serialize(self):
        """
        serialize returns the ECDSA signature in the more strict DER format.  Note
        that the serialized bytes returned do not include the appended hash type
        used in Decred signature scripts.
                
        encoding/asn1 is broken so we hand roll this output:
        0x30 <length> 0x02 <length r> r 0x02 <length s> s
        """
        # Curve order and halforder, used to tame ECDSA malleability (see BIP-0062)
        order     = Curve.N
        halforder = order>>1
        # low 'S' malleability breaker
        sigS = self.s
        if sigS > halforder: 
            sigS = order - sigS
        # Ensure the encoded bytes for the r and s values are canonical and
        # thus suitable for DER encoding.
        rb = canonicalizeInt(self.r)
        sb = canonicalizeInt(sigS)

        # total length of returned signature is 1 byte for each magic and
        # length (6 total), plus lengths of r and s
        length = 6 + len(rb) + len(sb)
        b = ByteArray(0, length=length)

        b[0] = 0x30
        b[1] = ByteArray(length - 2, length=1)
        b[2] = 0x02
        b[3] = ByteArray(len(rb), length=1)
        offset = 4
        b[offset] = rb
        offset += len(rb)
        b[offset] = 0x02
        offset +=1
        b[offset] = ByteArray(len(sb), length=1)
        offset += 1
        b[offset] = sb
        return b

class ScriptTokenizer:
    """
    ScriptTokenizer provides a facility for easily and efficiently tokenizing
    transaction scripts without creating allocations.  Each successive opcode is
    parsed with the Next function, which returns false when iteration is
    complete, either due to successfully tokenizing the entire script or
    encountering a parse error.  In the case of failure, the Err function may be
    used to obtain the specific parse error.
    
    Upon successfully parsing an opcode, the opcode and data associated with it
    may be obtained via the Opcode and Data functions, respectively.
    """
    def __init__(self, version, script):
        self.script = script
        self.version = version
        self.offset = 0
        self.op = None
        self.d = None
        self.err = None
    def next(self):
        """
        next attempts to parse the next opcode and returns whether or not it was
        successful.  It will not be successful if invoked when already at the end of
        the script, a parse failure is encountered, or an associated error already
        exists due to a previous parse failure.
        
        In the case of a true return, the parsed opcode and data can be obtained with
        the associated functions and the offset into the script will either point to
        the next opcode or the end of the script if the final opcode was parsed.
        
        In the case of a false return, the parsed opcode and data will be the last
        successfully parsed values (if any) and the offset into the script will
        either point to the failing opcode or the end of the script if the function
        was invoked when already at the end of the script.
        
        Invoking this function when already at the end of the script is not
        considered an error and will simply return false.
        """
        if self.done():
            return False
        opcodeArrayRef = opcode.opcodeArray

        op = opcodeArrayRef[self.script[self.offset]]
        if op.length == 1:
            # No additional data.  Note that some of the opcodes, notably OP_1NEGATE,
            # OP_0, and OP_[1-16] represent the data themselves.
            self.offset += 1
            self.op = op
            self.d = ByteArray(b'')
            return True
        elif op.length > 1:
            # Data pushes of specific lengths -- OP_DATA_[1-75].
            script = self.script[self.offset:]
            if len(script) < op.length:
                self.err = Exception("opcode %s requires %d bytes, but script only has %d remaining" % (op.name, op.length, len(script)))
                return False

            # Move the offset forward and set the opcode and data accordingly.
            self.offset += op.length
            self.op = op
            self.d = script[1:op.length]
            return True
        elif op.length < 0:
            # Data pushes with parsed lengths -- OP_PUSHDATA{1,2,4}.
            script = self.script[self.offset+1:]
            if len(script) < -op.length:
                self.err = Exception("opcode %s requires %d bytes, but script only has %d remaining" % (op.name, -op.length, len(script)))
                return False

            # Next -length bytes are little endian length of data.
            if op.length == -1:
                dataLen = script[0]
            elif op.length == -2:
                dataLen = script[:2].unLittle().int()
            elif op.length == -4:
                dataLen = script[:4].unLittle().int()
            else:
                self.err = Exception("invalid opcode length %d" % op.length)
                return False

            # Move to the beginning of the data.
            script = script[-op.length:]

            # Disallow entries that do not fit script or were sign extended.
            if dataLen > len(script) or dataLen < 0:
                self.err = Exception("opcode %s pushes %d bytes, but script only has %d remaining" % (op.name, dataLen, len(script)))
                return False

            # Move the offset forward and set the opcode and data accordingly.
            self.offset += 1 - op.length + dataLen
            self.op = op
            self.d = script[:dataLen]
            return False

        # The only remaining case is an opcode with length zero which is
        # impossible.
        raise Exception("unreachable")
    def done(self):
        """ 
        Script parsing has completed 
        
        Returns: 
            bool: True if script parsing complete.
        """
        return self.err != None or self.offset >= len(self.script)
    def opcode(self):
        """
        The current step's opcode

        Returns:
            int: the opcode. See crypto.opcode for more information.
        """
        if self.op is None:
            return None
        return self.op.value
    def data(self):
        """
        Data returns the data associated with the most recently successfully parsed
        opcode.

        Returns:
            ByteArray: The data
        """
        return self.d
    def byteIndex(self):
        """
        ByteIndex returns the current offset into the full script that will be 
        parsed next and therefore also implies everything before it has already 
        been parsed.

        Returns:
            int: the current offset
        """
        return self.offset

def checkScriptParses(scriptVersion, script):
    """ 
    checkScriptParses returns None when the script parses without error. 
    
    Args:
        scriptVersion (int): The script version.
        script (ByteArray): The script.

    Returns:
        None or Exception: None on success. Exception is returned, not raised. 
    """
    tokenizer = ScriptTokenizer(scriptVersion, script)
    while tokenizer.next():
        pass
    return tokenizer.err

def finalOpcodeData(scriptVersion, script):
    """ 
    finalOpcodeData returns the data associated with the final opcode in the
    script.  It will return nil if the script fails to parse.

    Args:
        scriptVersion (int): The script version.
        script (ByteArray): The script.

    Returns:
        ByteArray: The data associated with the final script opcode.
    """
    # Avoid unnecessary work.
    if len(script) == 0:
        return None

    data = None
    tokenizer = ScriptTokenizer(scriptVersion, script)
    while tokenizer.next():
        data = tokenizer.data
    if not tokenizer.err is None:
        return None
    return data

def canonicalizeInt(val):
    """
    canonicalizeInt returns the bytes for the passed big integer adjusted as
    necessary to ensure that a big-endian encoded integer can't possibly be
    misinterpreted as a negative number.  This can happen when the most
    significant bit is set, so it is padded by a leading zero byte in this case.
    Also, the returned bytes will have at least a single byte when the passed
    value is 0.  This is required for DER encoding.

    Args:
        val (int): The value to encode.

    Returns:
        ByteArray: The encoded integer with any necessary zero padding.
    """
    b = ByteArray(val)
    if len(b) == 0:
        b = ByteArray(0, length=1)
    if (b[0]&0x80) != 0:
        b = ByteArray(0, length=len(b)+1) | b
    return b

def hashToInt(h): 
    """
    hashToInt converts a hash value to an integer. There is some disagreement
    about how this is done. [NSA] suggests that this is done in the obvious
    manner, but [SECG] truncates the hash to the bit-length of the curve order
    first. We follow [SECG] because that's what OpenSSL does. Additionally,
    OpenSSL right shifts excess bits from the number if the hash is too large
    and we mirror that too.
    This is borrowed from crypto/ecdsa.

    Args:
        h (byte-like): The hash to convert.

    Returns:
        int: The integer.
    """
    orderBits = Curve.N.bit_length()
    orderBytes = (orderBits + 7) // 8
    if len(h) > orderBytes:
        h = h[:orderBytes]

    ret = int.from_bytes(h, byteorder="big")
    excess = len(h)*8 - orderBits
    if excess > 0:
        ret = ret >> excess
    return ret

def getScriptClass(version, script):
    """
    getScriptClass returns the class of the script passed.
    NonStandardTy will be returned when the script does not parse.

    Args:
        version (int): The script version.
        script (ByteArray): The script.

    Returns: 
        int: The script class.
    """
    if version != DefaultScriptVersion:
        return NonStandardTy

    return typeOfScript(version, script)

def typeOfScript(scriptVersion, script):
    """
    scriptType returns the type of the script being inspected from the known
    standard types.
        
    NOTE:  All scripts that are not version 0 are currently considered non
    standard.
    """
    if scriptVersion != DefaultScriptVersion:
        return NonStandardTy
    if isPubKeyHashScript(script):
        return PubKeyHashTy
    return NonStandardTy

def isPubKeyHashScript(script):
    return not extractPubKeyHash(script) is None

def extractPubKeyHash(script):
    """
    extractPubKeyHash extracts the public key hash from the passed script if it
    is a standard pay-to-pubkey-hash script. It will return None otherwise.
    """
    # A pay-to-pubkey-hash script is of the form:
    # OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    if (len(script) == 25 and
        script[0] == opcode.OP_DUP and
        script[1] == opcode.OP_HASH160 and
        script[2] == opcode.OP_DATA_20 and
        script[23] == opcode.OP_EQUALVERIFY and
        script[24] == opcode.OP_CHECKSIG):

        return script[3:23]
    return None

def extractScriptHash(pkScript):
    """
    extractScriptHash extracts the script hash from the passed script if it is a
    standard pay-to-script-hash script.  It will return nil otherwise.
        
    NOTE: This function is only valid for version 0 opcodes.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.
    """
    # A pay-to-script-hash script is of the form:
    #  OP_HASH160 <20-byte scripthash> OP_EQUAL
    if (len(pkScript) == 23 and
        pkScript[0] == opcode.OP_HASH160 and
        pkScript[1] == opcode.OP_DATA_20 and
        pkScript[22] == opcode.OP_EQUAL):

        return pkScript[2:22]
    return None

def isScriptHashScript(pkScript):
    """
    isScriptHashScript returns whether or not the passed script is a standard
    pay-to-script-hash script.
    """
    return extractScriptHash(pkScript) != None

def extractPubKey(script):
    """
    extractPubKey extracts either compressed or uncompressed public key from the
    passed script if it is a either a standard pay-to-compressed-secp256k1-pubkey
    or pay-to-uncompressed-secp256k1-pubkey script, respectively.  It will return
    nil otherwise.
    """
    pubkey = extractCompressedPubKey(script)
    if pubkey:
        return pubkey
    return extractUncompressedPubKey(script)

def extractCompressedPubKey(script):
    """
    extractCompressedPubKey extracts a compressed public key from the passed
    script if it is a standard pay-to-compressed-secp256k1-pubkey script.  It
    will return nil otherwise.
    """
    # pay-to-compressed-pubkey script is of the form:
    #  OP_DATA_33 <33-byte compresed pubkey> OP_CHECKSIG

    # All compressed secp256k1 public keys must start with 0x02 or 0x03.
    if (len(script) == 35 and
        script[34] == opcode.OP_CHECKSIG and
        script[0] == opcode.OP_DATA_33 and
        (script[1] == 0x02 or script[1] == 0x03)):
        return script[1:34]
    return None

def extractUncompressedPubKey(script):
    """
    extractUncompressedPubKey extracts an uncompressed public key from the
    passed script if it is a standard pay-to-uncompressed-secp256k1-pubkey
    script.  It will return nil otherwise.
    """
    # A pay-to-compressed-pubkey script is of the form:
    #  OP_DATA_65 <65-byte uncompressed pubkey> OP_CHECKSIG

    # All non-hybrid uncompressed secp256k1 public keys must start with 0x04.
    if (len(script) == 67 and
        script[66] == opcode.OP_CHECKSIG and
        script[0] == opcode.OP_DATA_65 and
        script[1] == 0x04):

        return script[1:66]
    return None

def isPubKeyScript(script):
    """
    isPubKeyScript returns whether or not the passed script is either a standard
    pay-to-compressed-secp256k1-pubkey or pay-to-uncompressed-secp256k1-pubkey
    script.
    """
    return extractPubKey(script) != None


def isStakeScriptHash(script, stakeOpcode):
    """
    isStakeScriptHash returns whether or not the passed public key script is a
    standard pay-to-script-hash script tagged with the provided stake opcode.
    """
    return extractStakeScriptHash(script, stakeOpcode) != None

def extractStakeScriptHash(script, stakeOpcode):
    """
    extractStakeScriptHash extracts a script hash from the passed public key
    script if it is a standard pay-to-script-hash script tagged with the provided
    stake opcode. It will return None otherwise.
    """
    if (len(script) == 24 and
        script[0] == stakeOpcode and
        script[1] == opcode.OP_HASH160 and
        script[2] == opcode.OP_DATA_20 and
        script[23] == opcode.OP_EQUAL):
        return script[3:23]
    return None

def extractStakePubKeyHash(script, stakeOpcode):
    """
    extractStakePubKeyHash extracts the public key hash from the passed script if
    it is a standard stake-tagged pay-to-pubkey-hash script with the provided
    stake opcode.  It will return nil otherwise.
    """
    # A stake-tagged pay-to-pubkey-hash is of the form:
    #   <stake opcode> <standard-pay-to-pubkey-hash script>

    # The script can't possibly be a stake-tagged pay-to-pubkey-hash if it
    # doesn't start with the given stake opcode.  Fail fast to avoid more work
    # below.
    if len(script) < 1 or script[0] != stakeOpcode:
        return None
    return extractPubKeyHash(script[1:])

class multiSigDetails(object):
    """
    multiSigDetails houses details extracted from a standard multisig script.
    """
    def __init__(self, pubkeys, numPubKeys, requiredSigs, valid):
        self.requiredSigs = requiredSigs
        self.numPubKeys = numPubKeys
        self.pubKeys = pubkeys
        self.valid = valid

def invalidMSDetails():
    return multiSigDetails([], 0, [], False)

def extractMultisigScriptDetails(scriptVersion, script, extractPubKeys):
    """
    extractMultisigScriptDetails attempts to extract details from the passed
    script if it is a standard multisig script.  The returned details struct will
    have the valid flag set to false otherwise.
    
    The extract pubkeys flag indicates whether or not the pubkeys themselves
    should also be extracted and is provided because extracting them results in
    an allocation that the caller might wish to avoid.  The pubKeys member of
    the returned details struct will be nil when the flag is false.
    
    NOTE: This function is only valid for version 0 scripts.  The returned
    details struct will always be empty and have the valid flag set to false for
    other script versions.
    """
    # The only currently supported script version is 0.
    if scriptVersion != 0:
        return invalidMSDetails()

    # A multi-signature script is of the form:
    #  NUM_SIGS PUBKEY PUBKEY PUBKEY ... NUM_PUBKEYS OP_CHECKMULTISIG

    # The script can't possibly be a multisig script if it doesn't end with
    # OP_CHECKMULTISIG or have at least two small integer pushes preceding it.
    # Fail fast to avoid more work below.
    if len(script) < 3 or script[len(script)-1] != opcode.OP_CHECKMULTISIG:
        return invalidMSDetails()
    # The first opcode must be a small integer specifying the number of
    # signatures required.
    tokenizer = ScriptTokenizer(scriptVersion, script)
    if not tokenizer.next() or not isSmallInt(tokenizer.opcode()):
        return invalidMSDetails()
    requiredSigs = asSmallInt(tokenizer.opcode())
    # The next series of opcodes must either push public keys or be a small
    # integer specifying the number of public keys.
    numPubkeys = 0
    pubkeys = []
    while tokenizer.next():
        data = tokenizer.data()
        if not isStrictPubKeyEncoding(data):
            break
        numPubkeys += 1
        if extractPubKeys:
            pubkeys.append(data)
    if tokenizer.done():
        return invalidMSDetails()
    # The next opcode must be a small integer specifying the number of public
    # keys required.
    op = tokenizer.opcode()
    if not isSmallInt(op) or asSmallInt(op) != numPubkeys:
        return invalidMSDetails()

    # There must only be a single opcode left unparsed which will be
    # OP_CHECKMULTISIG per the check above.
    if len(tokenizer.script)-tokenizer.byteIndex() != 1:
        return invalidMSDetails()
    return multiSigDetails(pubkeys, numPubkeys, requiredSigs, True)

# asSmallInt returns the passed opcode, which must be true according to
# isSmallInt(), as an integer.
def asSmallInt(op):
    if op == opcode.OP_0:
        return 0
    return int(op - (opcode.OP_1 - 1))

def isSmallInt(op):
    """
    isSmallInt returns whether or not the opcode is considered a small integer,
    which is an OP_0, or OP_1 through OP_16.

    NOTE: This function is only valid for version 0 opcodes.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.
    """
    return op == opcode.OP_0 or (op >= opcode.OP_1 and op <= opcode.OP_16)

def isStrictPubKeyEncoding(pubKey):
    """
    isStrictPubKeyEncoding returns whether or not the passed public key adheres
    to the strict encoding requirements.
    """
    if len(pubKey) == 33 and (pubKey[0] == 0x02 or pubKey[0] == 0x03):
        # Compressed
        return True
    if len(pubKey) == 65 and pubKey[0] == 0x04:
        # Uncompressed
        return True
    return False

def payToAddrScript(addr):
    """
    PayToAddrScript creates a new script to pay a transaction output to a the
    specified address.
    """
    if isinstance(addr, crypto.AddressPubKeyHash):
        if addr.sigType == crypto.STEcdsaSecp256k1:
            return payToPubKeyHashScript(addr.scriptAddress())
        elif addr.sigType == crypto.STEd25519:
            # return payToPubKeyHashEdwardsScript(addr.ScriptAddress())
            raise Exception("Edwards signatures not implemented")
        elif addr.sigType == crypto.STSchnorrSecp256k1:
            # return payToPubKeyHashSchnorrScript(addr.ScriptAddress())
            raise Exception("Schnorr signatures not implemented")
        raise Exception("unknown signature type %d" % addr.sigType)

    elif isinstance(addr, crypto.AddressScriptHash):
        return payToScriptHashScript(addr.scriptAddress())

    elif isinstance(addr, crypto.AddressSecpPubKey):
        return payToPubKeyScript(addr.scriptAddress())

    elif isinstance(addr, crypto.AddressEdwardsPubKey):
        # return payToEdwardsPubKeyScript(addr.ScriptAddress())
        raise Exception("Edwards signatures not implemented")

    elif isinstance(addr, crypto.AddressSecSchnorrPubKey):
        # return payToSchnorrPubKeyScript(addr.ScriptAddress())
        raise Exception("Schnorr signatures not implemented")

    raise Exception("unable to generate payment script for unsupported address type %s" % type(addr))

def payToPubKeyHashScript(pkHash):
    """
    payToAddrScript creates a new script to pay a transaction output to a the
    specified address.
    """
    if len(pkHash) != 20:
        raise Exception("cannot create script with pubkey hash length %d. expected length 20" % len(pkHash))
    script = ByteArray(b'')
    script += opcode.OP_DUP
    script += opcode.OP_HASH160
    script += addData(pkHash)
    script += opcode.OP_EQUALVERIFY
    script += opcode.OP_CHECKSIG
    return script

def payToScriptHashScript(scriptHash):
    """
    payToScriptHashScript creates a new script to pay a transaction output to a
    script hash. It is expected that the input is a valid hash.
    """
    script = ByteArray('')
    script += opcode.OP_HASH160
    script += addData(scriptHash)
    script += opcode.OP_EQUAL
    return script

def payToPubKeyScript(serializedPubKey):
    """
    payToPubkeyScript creates a new script to pay a transaction output to a
    public key. It is expected that the input is a valid pubkey.
    """
    script = ByteArray('')
    script += addData(serializedPubKey)
    script += opcode.OP_CHECKSIG
    return script

def decodeAddress(addr, net):
    """
    DecodeAddress decodes the string encoding of an address and returns the
    Address if it is a valid encoding for a known address type and is for the
    provided network.
    """
    # Switch on decoded length to determine the type.
    decoded, netID = crypto.b58CheckDecode(addr)

    if netID == net.PubKeyAddrID:
        return crypto.newAddressPubKey(decoded, net)
    elif netID == net.PubKeyHashAddrID:
        return crypto.newAddressPubKeyHash(decoded, net, crypto.STEcdsaSecp256k1)
    elif netID == net.PKHEdwardsAddrID:
        # return NewAddressPubKeyHash(decoded, net, STEd25519)
        raise Exception("Edwards signatures not implemented")
    elif netID == net.PKHSchnorrAddrID:
        # return NewAddressPubKeyHash(decoded, net, STSchnorrSecp256k1)
        raise Exception("Schnorr signatures not implemented")
    elif netID == net.ScriptHashAddrID:
        return crypto.newAddressScriptHashFromHash(decoded, net)
    raise Exception("unknown network ID %s" % netID)

def makePayToAddrScript(addrStr, chain):
    addr = decodeAddress(addrStr, chain)
    return payToAddrScript(addr)

def int2octets(v, rolen):
    """ https://tools.ietf.org/html/rfc6979#section-2.3.3"""
    out = ByteArray(v)

    # left pad with zeros if it's too short
    if len(out) < rolen:
        out2 = ByteArray(0, length=rolen)
        out2[rolen-len(out)] = out
        return out2

    # drop most significant bytes if it's too long
    if len(out) > rolen:
        out2 = ByteArray(0, length=rolen)
        out2[0] = out[len(out)-rolen:]
        return out2
    return out

def bits2octets(bits, rolen):
    """ https://tools.ietf.org/html/rfc6979#section-2.3.4"""
    z1 = hashToInt(bits)
    z2 = z1 - Curve.N
    if z2 < 0:
        return int2octets(z1, rolen)
    return int2octets(z2, rolen)

def nonceRFC6979(privKey, inHash, extra, version):
    """
    nonceRFC6979 generates an ECDSA nonce (`k`) deterministically according to
    RFC 6979. It takes a 32-byte hash as an input and returns 32-byte nonce to
    be used in ECDSA algorithm.
    """
    q = Curve.N
    x = privKey

    qlen = q.bit_length()
    holen = SHA256_SIZE
    rolen = (qlen + 7) >> 3
    bx = int2octets(x, rolen) + bits2octets(inHash, rolen)
    if len(extra) == 32:
        bx += extra
    if len(version) == 16 and len(extra) == 32:
        bx += extra
    if len(version) == 16 and len(extra) != 32:
        bx += ByteArray(0, length=32)
        bx += version 

    # Step B
    v = ByteArray(bytearray([1]*holen))

    # Step C (Go zeroes the all allocated memory)
    k = ByteArray(0, length=holen)

    # Step D
    k = mac(k,  v + ByteArray(0x00, length=1) + bx)

    # Step E
    v = mac(k, v)

    # Step F
    k = mac(k, v + 0x01 + bx)

    # Step G
    v = mac(k, v)

    # Step H
    while True:
        # Step H1
        t = ByteArray(b'')

        # Step H2
        while len(t)*8 < qlen:
            v = mac(k, v)
            t += v

        # Step H3
        secret = hashToInt(t)
        if secret >= 1 and secret < q:
            return secret

        k = mac(k, v + 0x00)
        v = mac(k, v)


def verifySig(pub, inHash, r, s):
    """
    verifySig verifies the signature in r, s of inHash using the public key, pub.

    Args: 
        pub (PublicKey): The public key.
        inHash (byte-like): The thing being signed.
        r (int): The R-parameter of the ECDSA signature.
        s (int): The S-parameter of the ECDSA signature.

    Returns:
        bool: True if the signature verifies the key. 
    """
    # See [NSA] 3.4.2
    N = Curve.N

    if r <= 0 or s <= 0:
        return False

    if r >= N or s >= N:
        return False

    e = hashToInt(inHash)

    w = crypto.modInv(s, N)

    u1 = (e * w) % N
    u2 = (r * w) % N


    x1, y1 = Curve.scalarBaseMult(u1)
    x2, y2 = Curve.scalarMult(pub.x, pub.y, u2)
    x, y = Curve.add(x1, y1, x2, y2)

    if x == 0 and y == 0:
        return False
    x = x % N
    return x == r

def signRFC6979(privateKey, inHash):
    """
    signRFC6979 generates a deterministic ECDSA signature according to RFC 6979
    and BIP 62.
    """
    N = Curve.N
    k = nonceRFC6979(privateKey, inHash, ByteArray(b''), ByteArray(b''))

    inv = crypto.modInv(k, N)
    r = Curve.scalarBaseMult(k)[0] % N

    if r == 0:
        raise Exception("calculated R is zero")

    e = hashToInt(inHash)
    s = privateKey.int() * r
    s += e
    s *= inv
    s = s % N

    if (N >> 1) > 1:
        s = N - s
    if s == 0:
        raise Exception("calculated S is zero")

    return Signature(r, s)

def putVarInt(val):
    """
    putVarInt serializes the provided number to a variable-length integer and
    according to the format described above returns the number of bytes of the
    encoded value.  The result is placed directly into the passed byte slice
    which must be at least large enough to handle the number of bytes returned by
    the varIntSerializeSize function or it will panic.
    """
    if val < 0xfd:
        return ByteArray(val, length=1)

    if val <= wire.MaxUint16:
        return reversed(ByteArray(0xfd, length=3)) | ByteArray(val, length=2).littleEndian()

    if val <= wire.MaxUint32:
        return reversed(ByteArray(0xfe, length=5)) | ByteArray(val, length=4).littleEndian()

    return reversed(ByteArray(0xff, length=9)) | ByteArray(val, length=8).littleEndian()

def addData(data):
    dataLen = len(data)
    b = ByteArray(b'')

    # When the data consists of a single number that can be represented
    # by one of the "small integer" opcodes, use that opcode instead of
    # a data push opcode followed by the number.
    if dataLen == 0 or (dataLen == 1 and data[0] == 0):
        b += opcode.OP_0
        return b
    elif dataLen == 1 and data[0] <= 16:
        b += opcode.OP_1-1+data[0]
        return b
    elif dataLen == 1 and data[0] == 0x81:
        b += opcode.OP_1NEGATE
        return b

    # Use one of the OP_DATA_# opcodes if the length of the data is small
    # enough so the data push instruction is only a single byte.
    # Otherwise, choose the smallest possible OP_PUSHDATA# opcode that
    # can represent the length of the data.
    if dataLen < opcode.OP_PUSHDATA1:
        b += (opcode.OP_DATA_1-1)+dataLen
    elif dataLen <= 0xff:
        b += opcode.OP_PUSHDATA1
        b += dataLen
    elif dataLen <= 0xffff:
        b += opcode.OP_PUSHDATA2
        b += ByteArray(dataLen).littleEndian()
    else:
        b += opcode.OP_PUSHDATA4
        b += ByteArray(dataLen, length=4).littleEndian()
    # Append the actual data.
    b += data
    return b

def signatureScript(tx, idx, subscript, hashType, privKey, compress):
    """
    SignatureScript creates an input signature script for tx to spend coins sent
    from a previous output to the owner of privKey. tx must include all
    transaction inputs and outputs, however txin scripts are allowed to be filled
    or empty. The returned script is calculated to be used as the idx'th txin
    sigscript for tx. subscript is the PkScript of the previous output being used
    as the idx'th input. privKey is serialized in either a compressed or
    uncompressed format based on compress. This format must match the same format
    used to generate the payment address, or the script validation will fail.
    """

    sig = rawTxInSignature(tx, idx, subscript, hashType, privKey.key)

    pubKey = privKey.pub

    if compress:
        pkData = pubKey.serializeCompressed()
    else:
        pkData = pubKey.serializeUncompressed()

    script = addData(sig)
    script += addData(pkData)

    return script

def rawTxInSignature(tx, idx, subScript, hashType, key):
    """
    rawTxInSignature returns the serialized ECDSA signature for the input idx of
    the given transaction, with hashType appended to it.
    
    NOTE: This function is only valid for version 0 scripts.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.
    """
    sigHash = calcSignatureHash(subScript, hashType, tx, idx, None)
    sig = signRFC6979(key, sigHash).serialize()
    return sig + ByteArray(hashType)

def calcSignatureHash(script, hashType, tx, idx, cachedPrefix):
    """
    CalcSignatureHash computes the signature hash for the specified input of
    the target transaction observing the desired signature hash type.  The
    cached prefix parameter allows the caller to optimize the calculation by
    providing the prefix hash to be reused in the case of SigHashAll without the
    SigHashAnyOneCanPay flag set.
    
    NOTE: This function is only valid for version 0 scripts.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.
    """
    scriptVersion = 0
    checkScriptParses(scriptVersion, script)

    # return calcSignatureHash(script, hashType, tx, idx, cachedPrefix)

    # The SigHashSingle signature type signs only the corresponding input
    # and output (the output with the same index number as the input).
    #
    # Since transactions can have more inputs than outputs, this means it
    # is improper to use SigHashSingle on input indices that don't have a
    # corresponding output.
    if hashType & sigHashMask == SigHashSingle and idx >= len(tx.txOut):
        raise Exception("attempt to sign single input at index %d >= %d outputs" % (idx, len(tx.txOut)))

    # Choose the inputs that will be committed to based on the signature
    # hash type.
    #
    # The SigHashAnyOneCanPay flag specifies that the signature will only
    # commit to the input being signed.  Otherwise, it will commit to all
    # inputs.
    txIns = tx.txIn
    signTxInIdx = idx
    if hashType&SigHashAnyOneCanPay != 0:
        txIns = tx.txIn[idx : idx+1]
        signTxInIdx = 0

    # The prefix hash commits to the non-witness data depending on the
    # signature hash type.  In particular, the specific inputs and output
    # semantics which are committed to are modified depending on the
    # signature hash type as follows:
    #
    # SigHashAll (and undefined signature hash types):
    #   Commits to all outputs.
    # SigHashNone:
    #   Commits to no outputs with all input sequences except the input
    #   being signed replaced with 0.
    # SigHashSingle:
    #   Commits to a single output at the same index as the input being
    #   signed.  All outputs before that index are cleared by setting the
    #   value to -1 and pkscript to nil and all outputs after that index
    #   are removed.  Like SigHashNone, all input sequences except the
    #   input being signed are replaced by 0.
    # SigHashAnyOneCanPay:
    #   Commits to only the input being signed.  Bit flag that can be
    #   combined with the other signature hash types.  Without this flag
    #   set, commits to all inputs.
    #
    # With the relevant inputs and outputs selected and the aforementioned
    # substitions, the prefix hash consists of the hash of the
    # serialization of the following fields:
    #
    # 1) txversion|(SigHashSerializePrefix<<16) (as little-endian uint32)
    # 2) number of inputs (as varint)
    # 3) per input:
    #    a) prevout hash (as little-endian uint256)
    #    b) prevout index (as little-endian uint32)
    #    c) prevout tree (as single byte)
    #    d) sequence (as little-endian uint32)
    # 4) number of outputs (as varint)
    # 5) per output:
    #    a) output amount (as little-endian uint64)
    #    b) pkscript version (as little-endian uint16)
    #    c) pkscript length (as varint)
    #    d) pkscript (as unmodified bytes)
    # 6) transaction lock time (as little-endian uint32)
    # 7) transaction expiry (as little-endian uint32)
    #
    # In addition, an optimization for SigHashAll is provided when the
    # SigHashAnyOneCanPay flag is not set.  In that case, the prefix hash
    # can be reused because only the witness data has been modified, so
    # the wasteful extra O(N^2) hash can be avoided.
    prefixHash = ByteArray(b'')
    if (SigHashOptimization and not cachedPrefix is None and
        hashType&sigHashMask == SigHashAll and
        (hashType&SigHashAnyOneCanPay).iszero()):

        prefixHash = cachedPrefix
    else:
        # Choose the outputs to commit to based on the signature hash
        # type.
        #
        # As the names imply, SigHashNone commits to no outputs and
        # SigHashSingle commits to the single output that corresponds
        # to the input being signed.  However, SigHashSingle is also a
        # bit special in that it commits to cleared out variants of all
        # outputs prior to the one being signed.  This is required by
        # consensus due to legacy reasons.
        #
        # All other signature hash types, such as SighHashAll commit to
        # all outputs.  Note that this includes undefined hash types as well.
        txOuts = tx.txOut
        requiredSigs = hashType & sigHashMask
        if requiredSigs == SigHashNone:
            txOuts = []
        elif requiredSigs == SigHashSingle:
            txOuts = tx.txOut[:idx+1]

        expectedSize = sigHashPrefixSerializeSize(hashType, txIns, txOuts, idx)

        prefixBuf = ByteArray(b'')

        # Commit to the version and hash serialization type.
        prefixBuf += ByteArray(tx.version | (SigHashSerializePrefix<<16), length=4).littleEndian()

        # Commit to the relevant transaction inputs.
        prefixBuf += putVarInt(len(txIns))
        for txInIdx, txIn in enumerate(txIns):
            # Commit to the outpoint being spent.
            prevOut = txIn.previousOutPoint
            prefixBuf += prevOut.hash
            prefixBuf += ByteArray(prevOut.index, length=4).littleEndian() # uint32
            prefixBuf += ByteArray(prevOut.tree, length=1)

            # Commit to the sequence.  In the case of SigHashNone
            # and SigHashSingle, commit to 0 for everything that is
            # not the input being signed instead.
            sequence = txIn.sequence
            if ((hashType&sigHashMask) == SigHashNone or (hashType&sigHashMask) == SigHashSingle) and txInIdx != signTxInIdx:
                sequence = 0
            prefixBuf += ByteArray(sequence, length=4).littleEndian()

        # Commit to the relevant transaction outputs.
        prefixBuf += putVarInt(len(txOuts))

        for txOutIdx, txOut in enumerate(txOuts):
            # Commit to the output amount, script version, and
            # public key script.  In the case of SigHashSingle,
            # commit to an output amount of -1 and a nil public
            # key script for everything that is not the output
            # corresponding to the input being signed instead.
            value = txOut.value
            pkScript = txOut.pkScript
            if hashType&sigHashMask == SigHashSingle and txOutIdx != idx:
                value = -1
                pkScript = b''
            prefixBuf += ByteArray(value, length=8).littleEndian()
            prefixBuf += ByteArray(txOut.version, length=2).littleEndian()
            prefixBuf += putVarInt(len(pkScript))
            prefixBuf += pkScript

        # Commit to the lock time and expiry.
        prefixBuf += ByteArray(tx.lockTime, length=4).littleEndian()
        prefixBuf += ByteArray(tx.expiry, length=4).littleEndian()
        if len(prefixBuf) != expectedSize:
            raise Exception("incorrect prefix serialization size %i != %i" % (len(prefixBuf), expectedSize))
        prefixHash = hashH(prefixBuf.bytes())

    # The witness hash commits to the input witness data depending on
    # whether or not the signature hash type has the SigHashAnyOneCanPay
    # flag set.  In particular the semantics are as follows:
    #
    # SigHashAnyOneCanPay:
    #   Commits to only the input being signed.  Without this flag set,
    #   commits to all inputs with the reference scripts cleared by setting
    #   them to nil.
    #
    # With the relevant inputs selected, and the aforementioned substitutions,
    # the witness hash consists of the hash of the serialization of the
    # following fields:
    #
    # 1) txversion|(SigHashSerializeWitness<<16) (as little-endian uint32)
    # 2) number of inputs (as varint)
    # 3) per input:
    #    a) length of prevout pkscript (as varint)
    #    b) prevout pkscript (as unmodified bytes)

    expectedSize = sigHashWitnessSerializeSize(txIns, script)
    witnessBuf = ByteArray(b'')

    # Commit to the version and hash serialization type.
    version = ByteArray(tx.version, length=4) | (SigHashSerializeWitness<<16)
    witnessBuf += version.littleEndian()

    # Commit to the relevant transaction inputs.
    witnessBuf += putVarInt(len(txIns))
    for txInIdx in range(len(txIns)):
        # Commit to the input script at the index corresponding to the
        # input index being signed.  Otherwise, commit to a nil script
        # instead.
        commitScript = script
        if txInIdx != signTxInIdx:
            commitScript = b''
        witnessBuf += putVarInt(len(commitScript))
        witnessBuf += commitScript
    if len(witnessBuf) != expectedSize:
        raise Exception("incorrect witness serialization size %i != %i" % (len(witnessBuf), expectedSize))
    witnessHash = hashH(witnessBuf.bytes())

    # The final signature hash (message to sign) is the hash of the
    # serialization of the following fields:
    #
    # 1) the hash type (as little-endian uint32)
    # 2) prefix hash (as produced by hash function)
    # 3) witness hash (as produced by hash function)
    sigHashBuf = ByteArray(0, length=HASH_SIZE*2+4)
    sigHashBuf[0] = ByteArray(hashType, length=4).littleEndian()
    sigHashBuf[4] = prefixHash
    sigHashBuf[4+HASH_SIZE] = witnessHash
    h = hashH(sigHashBuf.bytes())
    return h

def sigHashPrefixSerializeSize(hashType, txIns, txOuts, signIdx): 
    """
    sigHashPrefixSerializeSize returns the number of bytes the passed parameters
    would take when encoded with the format used by the prefix hash portion of
    the overall signature hash.
    1) 4 bytes version/serialization type
    2) number of inputs varint
    3) per input:
       a) 32 bytes prevout hash
       b) 4 bytes prevout index
       c) 1 byte prevout tree
       d) 4 bytes sequence
    4) number of outputs varint
    5) per output:
       a) 8 bytes amount
       b) 2 bytes script version
       c) pkscript len varint (1 byte if not SigHashSingle output)
       d) N bytes pkscript (0 bytes if not SigHashSingle output)
    6) 4 bytes lock time
    7) 4 bytes expiry
    """
    numTxIns = len(txIns)
    numTxOuts = len(txOuts)
    size = (4 + varIntSerializeSize(numTxIns) + numTxIns*(HASH_SIZE+4+1+4) +
        varIntSerializeSize(numTxOuts) + numTxOuts*(8+2) + 4 + 4)
    for txOutIdx, txOut in enumerate(txOuts):
        pkScript = txOut.pkScript
        if hashType&sigHashMask == SigHashSingle and txOutIdx != signIdx:
            pkScript = b''
        size += varIntSerializeSize(len(pkScript))
        size += len(pkScript)
    return size

def sigHashWitnessSerializeSize(txIns, signScript):
    """
    sigHashWitnessSerializeSize returns the number of bytes the passed parameters
    would take when encoded with the format used by the witness hash portion of
    the overall signature hash.
    """
    # 1) 4 bytes version/serialization type
    # 2) number of inputs varint
    # 3) per input:
    #    a) prevout pkscript varint (1 byte if not input being signed)
    #    b) N bytes prevout pkscript (0 bytes if not input being signed)
    #
    # NOTE: The prevout pkscript is replaced by nil for all inputs except
    # the input being signed.  Thus, all other inputs (aka numTxIns-1) commit
    # to a nil script which gets encoded as a single 0x00 byte.  This is
    # because encoding 0 as a varint results in 0x00 and there is no script
    # to write.  So, rather than looping through all inputs and manually
    # calculating the size per input, use (numTxIns - 1) as an
    # optimization.
    numTxIns = len(txIns)
    return 4 + varIntSerializeSize(numTxIns) + (numTxIns - 1) + varIntSerializeSize(len(signScript)) +  len(signScript)

def pubKeyHashToAddrs(pkHash, params):
    """
    pubKeyHashToAddrs is a convenience function to attempt to convert the
    passed hash to a pay-to-pubkey-hash address housed within an address
    list.  It is used to consolidate common code.
    """
    return [crypto.newAddressPubKeyHash(pkHash, params, crypto.STEcdsaSecp256k1)]

def scriptHashToAddrs(scriptHash, params):
    """
    scriptHashToAddrs is a convenience function to attempt to convert the passed
    hash to a pay-to-script-hash address housed within an address list.  It is
    used to consolidate common code.
    """
    return [crypto.newAddressScriptHashFromHash(scriptHash, params)]

def extractPkScriptAddrs(version, pkScript, chainParams):
    """
    extractPkScriptAddrs returns the type of script, addresses and required
    signatures associated with the passed PkScript.  Note that it only works for
    'standard' transaction script types.  Any data such as public keys which are
    invalid are omitted from the results.
    
    NOTE: This function only attempts to identify version 0 scripts.  The return
    value will indicate a nonstandard script type for other script versions along
    with an invalid script version error.
    """
    if version != 0:
        raise Exception("invalid script version")

    # Check for pay-to-pubkey-hash script.
    pkHash = extractPubKeyHash(pkScript)
    if pkHash:
        return PubKeyHashTy, pubKeyHashToAddrs(pkHash, chainParams), 1

    # Check for pay-to-script-hash.
    scriptHash = extractScriptHash(pkScript)
    if scriptHash:
        return ScriptHashTy, scriptHashToAddrs(scriptHash, chainParams), 1

    # Check for pay-to-pubkey script.
    data = extractPubKey(pkScript)
    if data:
        addrs = []
        pk = Curve.parsePubKey(data)
        addrs = [crypto.AddressSecpPubKey(pk.serializeCompressed(), chainParams)]
        return PubKeyTy, addrs, 1

    # Check for multi-signature script.
    details = extractMultisigScriptDetails(version, pkScript, True)
    if details.valid:
        # Convert the public keys while skipping any that are invalid.
        addrs = []
        for encodedPK in details.pubKeys:
            pk = Curve.parsePubKey(encodedPK)
            addrs.append(crypto.AddressSecpPubKey(pk.serializeCompressed(), chainParams))
        return MultiSigTy, addrs, details.requiredSigs

    # Check for stake submission script.  Only stake-submission-tagged
    # pay-to-pubkey-hash and pay-to-script-hash are allowed.
    pkHash = extractStakePubKeyHash(pkScript, opcode.OP_SSTX)
    if pkHash:
        return StakeSubmissionTy, pubKeyHashToAddrs(hash, chainParams), 1
    scriptHash = extractStakeScriptHash(pkScript, opcode.OP_SSTX)
    if scriptHash:
        return StakeSubmissionTy, scriptHashToAddrs(hash, chainParams), 1

    # Check for stake generation script.  Only stake-generation-tagged
    # pay-to-pubkey-hash and pay-to-script-hash are allowed.
    pkHash = extractStakePubKeyHash(pkScript, opcode.OP_SSGEN)
    if pkHash:
        return StakeGenTy, pubKeyHashToAddrs(pkHash, chainParams), 1
    scriptHash = extractStakeScriptHash(pkScript, opcode.OP_SSGEN)
    if scriptHash:
        return StakeGenTy, scriptHashToAddrs(scriptHash, chainParams), 1

    # Check for stake revocation script.  Only stake-revocation-tagged
    # pay-to-pubkey-hash and pay-to-script-hash are allowed.
    pkHash = extractStakePubKeyHash(pkScript, opcode.OP_SSRTX)
    if pkHash:
        return StakeRevocationTy, pubKeyHashToAddrs(pkHash, chainParams), 1
    scriptHash = extractStakeScriptHash(pkScript, opcode.OP_SSRTX)
    if scriptHash:
        return StakeRevocationTy, scriptHashToAddrs(scriptHash, chainParams), 1

    # Check for stake change script.  Only stake-change-tagged
    # pay-to-pubkey-hash and pay-to-script-hash are allowed.
    pkHash = extractStakePubKeyHash(pkScript, opcode.OP_SSTXCHANGE)
    if pkHash:
        return StakeSubChangeTy, pubKeyHashToAddrs(pkHash, chainParams), 1
    scriptHash = extractStakeScriptHash(pkScript, opcode.OP_SSTXCHANGE)
    if scriptHash:
        return StakeSubChangeTy, scriptHashToAddrs(scriptHash, chainParams), 1

    # EVERYTHING AFTER TIHS IS UN-IMPLEMENTED
    raise Exception("unsupported script")

def sign(privKey, chainParams, tx, idx, subScript, hashType, sigType):
    scriptClass, addresses, nrequired = extractPkScriptAddrs(DefaultScriptVersion, subScript, chainParams)

    if scriptClass == PubKeyHashTy:
        # look up key for address
        # key = acct.getPrivKeyForAddress(addresses[0])
        script = signatureScript(tx, idx, subScript, hashType, privKey, True)
    else:
        raise Exception("un-implemented script class")

    return script, scriptClass, addresses, nrequired

def mergeScripts(chainParams, tx, idx, pkScript, scriptClass, addresses, nRequired, sigScript, prevScript):
    """
    mergeScripts merges sigScript and prevScript assuming they are both
    partial solutions for pkScript spending output idx of tx. class, addresses
    and nrequired are the result of extracting the addresses from pkscript.
    The return value is the best effort merging of the two scripts. Calling this
    function with addresses, class and nrequired that do not match pkScript is
    an error and results in undefined behaviour.
        
    NOTE: This function is only valid for version 0 scripts.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.
    """
    # TODO(oga) the scripthash and multisig paths here are overly
    # inefficient in that they will recompute already known data.
    # some internal refactoring could probably make this avoid needless
    # extra calculations.
    scriptVersion = 0
    if scriptClass == ScriptHashTy:
        # Nothing to merge if either the new or previous signature
        # scripts are empty or fail to parse.

        if len(sigScript) == 0 or checkScriptParses(scriptVersion, sigScript) != None:
            return prevScript
        if len(prevScript) == 0 or checkScriptParses(scriptVersion, prevScript) != None:
            return sigScript

        # Remove the last push in the script and then recurse.
        # this could be a lot less inefficient.
        #
        # Assume that final script is the correct one since it was just
        # made and it is a pay-to-script-hash.
        script = finalOpcodeData(scriptVersion, sigScript)

        # We already know this information somewhere up the stack,
        # therefore the error is ignored.
        scriptClass, addresses, nrequired = extractPkScriptAddrs(DefaultScriptVersion, script, chainParams)

        # Merge
        mergedScript = mergeScripts(chainParams, tx, idx, script, scriptClass, addresses, nrequired, sigScript, prevScript)

        # Reappend the script and return the result.
        finalScript = ByteArray(b'', length=0)
        finalScript += mergedScript
        finalScript += addData(script)
        return finalScript
    elif scriptClass == MultiSigTy:
        raise Exception("multisig signing unimplemented")
        # return mergeMultiSig(tx, idx, addresses, nRequired, pkScript,
        #   sigScript, prevScript)
    else:
        # It doesn't actually make sense to merge anything other than multiig
        # and scripthash (because it could contain multisig). Everything else
        # has either zero signature, can't be spent, or has a single signature
        # which is either present or not. The other two cases are handled
        # above. In the conflict case here we just assume the longest is
        # correct (this matches behaviour of the reference implementation).
        if prevScript is None or len(sigScript) > len(prevScript):
            return sigScript
        return prevScript

def signTxOutput(privKey, chainParams, tx, idx, pkScript, hashType, previousScript, sigType):
    """
    signTxOutput signs output idx of the given tx to resolve the script given in
    pkScript with a signature type of hashType. Any keys required will be
    looked up by calling getKey() with the string of the given address.
    Any pay-to-script-hash signatures will be similarly looked up by calling
    getScript. If previousScript is provided then the results in previousScript
    will be merged in a type-dependent manner with the newly generated.
    signature script.
            
    NOTE: This function is only valid for version 0 scripts.  Since the function
    does not accept a script version, the results are undefined for other script
    versions.
    """

    sigScript, scriptClass, addresses, nrequired = sign(privKey, chainParams, tx, idx, pkScript, hashType, sigType)

    isStakeType = (scriptClass == StakeSubmissionTy or
        scriptClass == StakeSubChangeTy or
        scriptClass == StakeGenTy or
        scriptClass == StakeRevocationTy)
    if isStakeType:
        # scriptClass = getStakeOutSubclass(pkScript)
        raise Exception("unimplemented")

    if scriptClass == ScriptHashTy:
        raise Exception("ScriptHashTy signing unimplemented")
        # # TODO keep the sub addressed and pass down to merge.
        # realSigScript, _, _, _ = sign(privKey, chainParams, tx, idx, sigScript, hashType, sigType)

        # # Append the p2sh script as the last push in the script.
        # script = ByteArray(b'')
        # script += realSigScript
        # script += sigScript
        # script += realSigScript
        # script += addData(sigScript)

        # sigScript = script
        # # TODO keep a copy of the script for merging.

    # Merge scripts. with any previous data, if any.
    mergedScript = mergeScripts(chainParams, tx, idx, pkScript, scriptClass, addresses, nrequired, sigScript, previousScript)
    return mergedScript

class TestTxScript(unittest.TestCase):
    def test_var_int_serialize(self):
        """
        TestVarIntSerializeSize ensures the serialize size for variable length
        integers works as intended.
        """
        tests = [
            (0, 1),                  # Single byte encoded
            (0xfc, 1),               # Max single byte encoded
            (0xfd, 3),               # Min 3-byte encoded
            (0xffff, 3),             # Max 3-byte encoded
            (0x10000, 5),            # Min 5-byte encoded
            (0xffffffff, 5),         # Max 5-byte encoded
            (0x100000000, 9),        # Min 9-byte encoded
            (0xffffffffffffffff, 9), # Max 9-byte encoded
        ]

        for i, (val, size) in enumerate(tests):
            self.assertEqual(varIntSerializeSize(val), size, msg="test at index %d" % i)
    def test_calc_signature_hash(self):
        """ TestCalcSignatureHash does some rudimentary testing of msg hash calculation. """
        tx = msgtx.MsgTx.new()
        for i in range(3):
            txIn = msgtx.TxIn(msgtx.OutPoint(
                txHash = hashH(ByteArray(i, length=1).bytes()),
                idx = i,
                tree = 0,
            ), 0)
            txIn.sequence = 0xFFFFFFFF

            tx.addTxIn(txIn)
        for i in range(2):
            txOut = msgtx.TxOut()
            txOut.pkScript = ByteArray("51", length=1)
            txOut.value = 0x0000FF00FF00FF00
            tx.addTxOut(txOut)

        want = ByteArray("4ce2cd042d64e35b36fdbd16aff0d38a5abebff0e5e8f6b6b31fcd4ac6957905")
        script = ByteArray("51", length=1)

        msg1 = calcSignatureHash(script, SigHashAll, tx, 0, None)

        prefixHash = tx.hash()
        msg2 = calcSignatureHash(script, SigHashAll, tx, 0, prefixHash)

        self.assertEqual(msg1, want)

        self.assertEqual(msg2, want)

        self.assertEqual(msg1, msg2)

        # Move the index and make sure that we get a whole new hash, despite
        # using the same TxOuts.
        msg3 = calcSignatureHash(script, SigHashAll, tx, 1, prefixHash)

        self.assertNotEqual(msg1, msg3)
    def test_script_tokenizer(self):
        """
        TestScriptTokenizer ensures a wide variety of behavior provided by the script
        tokenizer performs as expected.
        """

        # Add both positive and negative tests for OP_DATA_1 through OP_DATA_75.
        tests = []
        for op in range(opcode.OP_DATA_1, opcode.OP_DATA_75):
            data = ByteArray([1]*op)
            tests.append((
                "OP_DATA_%d" % op,
                ByteArray(op, length=1) + data,
                ((op, data, 1 + op), ),
                1 + op,
                None,
            ))

            # Create test that provides one less byte than the data push requires.
            tests.append((
                "short OP_DATA_%d" % op,
                ByteArray(op) + data[1:],
                None,
                0,
                Exception,
            ))

        # Add both positive and negative tests for OP_PUSHDATA{1,2,4}.
        data = ByteArray([1]*76)
        tests.extend([(
            "OP_PUSHDATA1",
            ByteArray(opcode.OP_PUSHDATA1) + ByteArray(0x4c) + ByteArray([0x01]*76),
            ((opcode.OP_PUSHDATA1, data, 2 + len(data)),),
            2 + len(data),
            None,
        ), (
            "OP_PUSHDATA1 no data length",
            ByteArray(opcode.OP_PUSHDATA1),
            None,
            0,
            Exception,
        ), (
            "OP_PUSHDATA1 short data by 1 byte",
            ByteArray(opcode.OP_PUSHDATA1) + ByteArray(0x4c) + ByteArray([0x01]*75),
            None,
            0,
            Exception,
        ), (
            "OP_PUSHDATA2",
            ByteArray(opcode.OP_PUSHDATA2) + ByteArray(0x4c00) + ByteArray([0x01]*76),
            ((opcode.OP_PUSHDATA2, data, 3 + len(data)),),
            3 + len(data),
            None,
        ), (
            "OP_PUSHDATA2 no data length",
            ByteArray(opcode.OP_PUSHDATA2),
            None,
            0,
            Exception,
        ), (
            "OP_PUSHDATA2 short data by 1 byte",
            ByteArray(opcode.OP_PUSHDATA2) + ByteArray(0x4c00) + ByteArray([0x01]*75),
            None,
            0,
            Exception,
        ), (
            "OP_PUSHDATA4",
            ByteArray(opcode.OP_PUSHDATA4) + ByteArray(0x4c000000) + ByteArray([0x01]*76),
            ((opcode.OP_PUSHDATA4, data, 5 + len(data)),),
            5 + len(data),
            None,
        ), (
            "OP_PUSHDATA4 no data length",
            ByteArray(opcode.OP_PUSHDATA4),
            None,
            0,
            Exception,
        ), (
            "OP_PUSHDATA4 short data by 1 byte",
            ByteArray(opcode.OP_PUSHDATA4) + ByteArray(0x4c000000) + ByteArray([0x01]*75),
            None,
            0,
            Exception,
        )])

        # Add tests for OP_0, and OP_1 through OP_16 (small integers/true/false).
        opcodes = ByteArray(opcode.OP_0)
        for op in range(opcode.OP_1, opcode.OP_16):
            opcodes += op
        for op in opcodes:
            tests.append((
                "OP_%d" % op,
                ByteArray(op),
                ((op, None, 1),),
                1,
                None,
            ))

        # Add various positive and negative tests for  multi-opcode scripts.
        tests.extend([(
            "pay-to-pubkey-hash",
            ByteArray(opcode.OP_DUP) + ByteArray(opcode.OP_HASH160) + ByteArray(opcode.OP_DATA_20) + ByteArray([0x01]*20) + ByteArray(opcode.OP_EQUAL) + ByteArray(opcode.OP_CHECKSIG),
            (
                (opcode.OP_DUP, None, 1), (opcode.OP_HASH160, None, 2),
                (opcode.OP_DATA_20, ByteArray([0x01]*20), 23),
                (opcode.OP_EQUAL, None, 24), (opcode.OP_CHECKSIG, None, 25),
            ),
            25,
            None,
        ), (
            "almost pay-to-pubkey-hash (short data)",
            ByteArray(opcode.OP_DUP) + ByteArray(opcode.OP_HASH160) + ByteArray(opcode.OP_DATA_20) + ByteArray([0x01]*17) + ByteArray(opcode.OP_EQUAL) + ByteArray(opcode.OP_CHECKSIG),
            (
                (opcode.OP_DUP, None, 1), (opcode.OP_HASH160, None, 2),
            ),
            2,
            Exception,
        ), (
            "almost pay-to-pubkey-hash (overlapped data)",
            ByteArray(opcode.OP_DUP) + ByteArray(opcode.OP_HASH160) + ByteArray(opcode.OP_DATA_20) + ByteArray([0x01]*19) + ByteArray(opcode.OP_EQUAL) + ByteArray(opcode.OP_CHECKSIG),
            (
                (opcode.OP_DUP, None, 1), (opcode.OP_HASH160, None, 2),
                (opcode.OP_DATA_20, ByteArray([0x01]*19) + ByteArray(opcode.OP_EQUAL), 23),
                (opcode.OP_CHECKSIG, None, 24),
            ),
            24,
            None,
        ), (
            "pay-to-script-hash",
            ByteArray(opcode.OP_HASH160) + ByteArray(opcode.OP_DATA_20) + ByteArray([0x01]*20) + ByteArray(opcode.OP_EQUAL),
            (
                (opcode.OP_HASH160, None, 1),
                (opcode.OP_DATA_20, ByteArray([0x01]*20), 22),
                (opcode.OP_EQUAL, None, 23),
            ),
            23,
            None,
        ), (
            "almost pay-to-script-hash (short data)",
            ByteArray(opcode.OP_HASH160) + ByteArray(opcode.OP_DATA_20) + ByteArray([0x01]*18) + ByteArray(opcode.OP_EQUAL),
            (
                (opcode.OP_HASH160, None, 1),
            ),
            1,
            Exception,
        ), (
            "almost pay-to-script-hash (overlapped data)",
            ByteArray(opcode.OP_HASH160) + ByteArray(opcode.OP_DATA_20) + ByteArray([0x01]*19) + ByteArray(opcode.OP_EQUAL),
            (
                (opcode.OP_HASH160, None, 1),
                (opcode.OP_DATA_20, ByteArray([0x01]*19) + ByteArray(opcode.OP_EQUAL), 22),
            ),
            22,
            None,
        )])

        scriptVersion = 0
        for test_name, test_script, test_expected, test_finalIdx, test_err in tests:
            tokenizer = ScriptTokenizer(scriptVersion, test_script)
            opcodeNum = 0
            while tokenizer.next():
                # Ensure Next never returns true when there is an error set.
                self.assertIs(tokenizer.err, None, msg="%s: Next returned true when tokenizer has err: %r" % (test_name, tokenizer.err))

                # Ensure the test data expects a token to be parsed.
                op = tokenizer.opcode()
                data = tokenizer.data
                self.assertFalse(opcodeNum >= len(test_expected), msg="%s: unexpected token '%r' (data: '%s')" % (test_name, op, data))
                expected_op, expected_data, expected_index = test_expected[opcodeNum]

                # Ensure the opcode and data are the expected values.
                self.assertEqual(op, expected_op, msg="%s: unexpected opcode -- got %d, want %d" % (test_name, op, expected_op))
                self.assertEqual(data, expected_data, msg="%s: unexpected data -- got %s, want %s" % (test_name, data, expected_data))

                tokenizerIdx = tokenizer.offset
                self.assertEqual(tokenizerIdx, expected_index, msg="%s: unexpected byte index -- got %d, want %d" % (test_name, tokenizerIdx, expected_index))

                opcodeNum += 1

            # Ensure the tokenizer claims it is done.  This should be the case
            # regardless of whether or not there was a parse error.
            self.assertTrue(tokenizer.done(), msg="%s: tokenizer claims it is not done" % test_name)

            # Ensure the error is as expected.
            if test_err is None:
                self.assertIs(tokenizer.err, None, msg="%s: unexpected tokenizer err -- got %r, want None" % (test_name, tokenizer.err))
            else:
                self.assertTrue(isinstance(tokenizer.err, test_err), msg="%s: unexpected tokenizer err -- got %r, want %r" % (test_name, tokenizer.err, test_err))

            # Ensure the final index is the expected value.
            tokenizerIdx = tokenizer.offset
            self.assertEqual(tokenizerIdx, test_finalIdx, msg="%s: unexpected final byte index -- got %d, want %d" % (test_name, tokenizerIdx, test_finalIdx))
    def test_sign_tx(self):
        """
        Based on dcrd TestSignTxOutput.
        """
        # make key
        # make script based on key.
        # sign with magic pixie dust.
        hashTypes = (
            SigHashAll,
            # SigHashNone,
            # SigHashSingle,
            # SigHashAll | SigHashAnyOneCanPay,
            # SigHashNone | SigHashAnyOneCanPay,
            # SigHashSingle | SigHashAnyOneCanPay,
        )
        signatureSuites = (
            crypto.STEcdsaSecp256k1,
            # crypto.STEd25519,
            # crypto.STSchnorrSecp256k1,
        )

        testValueIn = 12345
        tx = msgtx.MsgTx(
            serType = wire.TxSerializeFull,
            version = 1,
            txIn = [
                msgtx.TxIn(
                    previousOutPoint = msgtx.OutPoint(
                        txHash =  ByteArray(b''),
                        idx = 0,
                        tree =  0,
                    ),
                    sequence =    4294967295,
                    valueIn =     testValueIn,
                    blockHeight = 78901,
                    blockIndex =  23456,
                ),
                msgtx.TxIn(
                    previousOutPoint = msgtx.OutPoint(
                        txHash = ByteArray(b''),
                        idx = 1,
                        tree =  0,
                    ),
                    sequence =    4294967295,
                    valueIn =     testValueIn,
                    blockHeight = 78901,
                    blockIndex =  23456,
                ),
                msgtx.TxIn(
                    previousOutPoint = msgtx.OutPoint(
                        txHash = ByteArray(b''),
                        idx = 2,
                        tree =  0,
                    ),
                    sequence =    4294967295,
                    valueIn =     testValueIn,
                    blockHeight = 78901,
                    blockIndex =  23456,
                ),
            ],
            txOut = [
                msgtx.TxOut(
                    version = wire.DefaultPkScriptVersion,
                    value =   1,
                ),
                msgtx.TxOut(
                    version = wire.DefaultPkScriptVersion,
                    value =   2,
                ),
                msgtx.TxOut(
                    version = wire.DefaultPkScriptVersion,
                    value =   3,
                ),
            ],
            lockTime = 0,
            expiry = 0,
            cachedHash = None,
        )

        # Since the script engine is not implmented, hard code the keys and 
        # check that the script signature is the same as produced by dcrd.

        # For compressed keys
        tests = (
            ("b78a743c0c6557f24a51192b82925942ebade0be86efd7dad58b9fa358d3857c", "47304402203220ddaee5e825376d3ae5a0e20c463a45808e066abc3c8c33a133446a4c9eb002200f2b0b534d5294d9ce5974975ab5af11696535c4c76cadaed1fa327d6d210e19012102e11d2c0e415343435294079ac0774a21c8e6b1e6fd9b671cb08af43a397f3df1"),
            ("a00616c21b117ba621d4c72faf30d30cd665416bdc3c24e549de2348ac68cfb8", "473044022020eb42f1965c31987a4982bd8f654d86c1451418dd3ccc0a342faa98a384186b022021cd0dcd767e607df159dd25674469e1d172e66631593bf96023519d5c07c43101210224397bd81b0e80ec1bbfe104fb251b57eb0adcf044c3eec05d913e2e8e04396b"),
            ("8902ea1f64c6fb7aa40dfbe798f5dc53b466a3fc01534e867581936a8ecbff5b", "483045022100d71babc95de02df7be1e7b14c0f68fb5dcab500c8ef7cf8172b2ea8ad627533302202968ddc3b2f9ff07d3a736b04e74fa39663f028035b6d175de6a4ef90838b797012103255f71eab9eb2a7e3f822569484448acbe2880d61b4db61020f73fd54cbe370d"),
        )

        # For uncompressed keys
        # tests = (
        #     ("b78a743c0c6557f24a51192b82925942ebade0be86efd7dad58b9fa358d3857c", "483045022100e1bab52fe0b460c71e4a4226ada35ebbbff9959835fa26c70e2571ef2634a05b02200683f9bf8233ba89c5f9658041cc8edc56feef74cad238f060c3b04e0c4f1cb1014104e11d2c0e415343435294079ac0774a21c8e6b1e6fd9b671cb08af43a397f3df1c4d3fa86c79cfe4f9d13f1c31fd75de316cdfe913b03c07252b1f02f7ee15c9c"),
        #     ("a00616c21b117ba621d4c72faf30d30cd665416bdc3c24e549de2348ac68cfb8", "473044022029cf920fe059ca4d7e5d74060ed234ebcc7bca520dfed7238dc1e32a48d182a9022043141a443740815baf0caffc19ff7b948d41424832b4a9c6273be5beb15ed7ce01410424397bd81b0e80ec1bbfe104fb251b57eb0adcf044c3eec05d913e2e8e04396b422f7f8591e7a4030eddb635e753523bce3c6025fc4e97987adb385b08984e94"),
        #     ("8902ea1f64c6fb7aa40dfbe798f5dc53b466a3fc01534e867581936a8ecbff5b", "473044022015f417f05573c3201f96f5ae706c0789539e638a4a57915dc077b8134c83f1ff022001afa12cebd5daa04d7a9d261d78d0fb910294d78c269fe0b2aabc2423282fe5014104255f71eab9eb2a7e3f822569484448acbe2880d61b4db61020f73fd54cbe370d031fee342d455077982fe105e82added63ad667f0b616f3c2c17e1cc9205f3d1"),
        # )

        # Pay to Pubkey Hash (uncompressed)
        # secp256k1 := chainec.Secp256k1
        from tinydecred.pydecred import mainnet
        testingParams = mainnet
        for hashType in hashTypes:
            for suite in signatureSuites:
                for idx in range(len(tx.txIn)):
                    # var keyDB, pkBytes []byte
                    # var key chainec.PrivateKey
                    # var pk chainec.PublicKey
                    kStr, sigStr = tests[idx]

                    if suite == crypto.STEcdsaSecp256k1:
                        # k = Curve.generateKey(rand.Reader)
                        k = ByteArray(kStr)
                        privKey = crypto.privKeyFromBytes(k)
                        pkBytes = privKey.pub.serializeCompressed()
                    else:
                        raise Exception("test for signature suite %d not implemented" % suite)

                    address = crypto.newAddressPubKeyHash(crypto.hash160(pkBytes.bytes()), testingParams, suite)

                    pkScript = makePayToAddrScript(address.string(), testingParams)

                    # chainParams, tx, idx, pkScript, hashType, kdb, sdb, previousScript, sigType
                    sigScript = signTxOutput(privKey, testingParams, tx, idx, pkScript, hashType, None, suite)

                    self.assertEqual(sigScript, ByteArray(sigStr), msg="%d:%d:%d" % (hashType, idx, suite))
        return
    def test_addresses(self):
        from tinydecred.pydecred import mainnet, testnet
        from base58 import b58decode
        class test:
            def __init__(self, name="", addr="", saddr="", encoded="", valid=False, scriptAddress=None, f=None, net=None):
                self.name = name
                self.addr = addr
                self.saddr = saddr
                self.encoded = encoded
                self.valid = valid
                self.scriptAddress = scriptAddress
                self.f = f
                self.net = net
        
        addrPKH = crypto.newAddressPubKeyHash
        addrSH = crypto.newAddressScriptHash
        addrSHH = crypto.newAddressScriptHashFromHash
        addrPK = crypto.AddressSecpPubKey

        tests = []
        # Positive P2PKH tests.
        tests.append(test(
            name = "mainnet p2pkh",
            addr = "DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJu",
            encoded = "DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJu",
            valid = True,
            scriptAddress = ByteArray("2789d58cfa0957d206f025c2af056fc8a77cebb0"),
            f = lambda: addrPKH(
                ByteArray("2789d58cfa0957d206f025c2af056fc8a77cebb0"),
                mainnet,
                crypto.STEcdsaSecp256k1,
            ),
            net = mainnet,
        ))
        tests.append(test(
            name =    "mainnet p2pkh 2",
            addr =    "DsU7xcg53nxaKLLcAUSKyRndjG78Z2VZnX9",
            encoded = "DsU7xcg53nxaKLLcAUSKyRndjG78Z2VZnX9",
            valid =   True,
            scriptAddress = ByteArray("229ebac30efd6a69eec9c1a48e048b7c975c25f2"),
            f = lambda: addrPKH(
                ByteArray("229ebac30efd6a69eec9c1a48e048b7c975c25f2"),
                mainnet,
                crypto.STEcdsaSecp256k1,
            ),
            net = mainnet,
        ))
        tests.append(test(
            name =    "testnet p2pkh",
            addr =    "Tso2MVTUeVrjHTBFedFhiyM7yVTbieqp91h",
            encoded = "Tso2MVTUeVrjHTBFedFhiyM7yVTbieqp91h",
            valid =   True,
            scriptAddress = ByteArray("f15da1cb8d1bcb162c6ab446c95757a6e791c916"),
            f = lambda: addrPKH(
                ByteArray("f15da1cb8d1bcb162c6ab446c95757a6e791c916"),
                testnet, 
                crypto.STEcdsaSecp256k1
            ),
            net = testnet,
        ))

        # Negative P2PKH tests.
        tests.append(test(
            name = "p2pkh wrong hash length",
            addr = "",
            valid = False,
            f = lambda: addrPKH(
                ByteArray("000ef030107fd26e0b6bf40512bca2ceb1dd80adaa"),
                mainnet,
                crypto.STEcdsaSecp256k1,
            ),
        ))
        tests.append(test(
            name =  "p2pkh bad checksum",
            addr =  "TsmWaPM77WSyA3aiQ2Q1KnwGDVWvEkhip23",
            valid = False,
            net =   testnet,
        ))

        # Positive P2SH tests.
        tests.append(test(
            # Taken from transactions:
            # output: 3c9018e8d5615c306d72397f8f5eef44308c98fb576a88e030c25456b4f3a7ac
            # input:  837dea37ddc8b1e3ce646f1a656e79bbd8cc7f558ac56a169626d649ebe2a3ba.
            name =    "mainnet p2sh",
            addr =    "DcuQKx8BES9wU7C6Q5VmLBjw436r27hayjS",
            encoded = "DcuQKx8BES9wU7C6Q5VmLBjw436r27hayjS",
            valid =   True,
            scriptAddress = ByteArray("f0b4e85100aee1a996f22915eb3c3f764d53779a"),
            f = lambda: addrSH(
                ByteArray("512103aa43f0a6c15730d886cc1f0342046d20175483d90d7ccb657f90c489111d794c51ae"),
                mainnet,
            ),
            net = mainnet,
        ))
        tests.append(test(
            # Taken from transactions:
            # output: b0539a45de13b3e0403909b8bd1a555b8cbe45fd4e3f3fda76f3a5f52835c29d
            # input: (not yet redeemed at time test was written)
            name =    "mainnet p2sh 2",
            addr =    "DcqgK4N4Ccucu2Sq4VDAdu4wH4LASLhzLVp",
            encoded = "DcqgK4N4Ccucu2Sq4VDAdu4wH4LASLhzLVp",
            valid =   True,
            scriptAddress = ByteArray("c7da5095683436f4435fc4e7163dcafda1a2d007"),
            f = lambda: addrSHH(
                ByteArray("c7da5095683436f4435fc4e7163dcafda1a2d007"),
                mainnet,
            ),
            net = mainnet,
        ))
        tests.append(test(
            # Taken from bitcoind base58_keys_valid.
            name =    "testnet p2sh",
            addr =    "TccWLgcquqvwrfBocq5mcK5kBiyw8MvyvCi",
            encoded = "TccWLgcquqvwrfBocq5mcK5kBiyw8MvyvCi",
            valid =   True,
            scriptAddress = ByteArray("36c1ca10a8a6a4b5d4204ac970853979903aa284"),
            f = lambda: addrSHH(
                ByteArray("36c1ca10a8a6a4b5d4204ac970853979903aa284"),
                testnet,
            ),
            net = testnet,
        ))

        # Negative P2SH tests.
        tests.append(test(
            name =  "p2sh wrong hash length",
            addr =  "",
            valid = False,
            f = lambda: addrSHH(
                ByteArray("00f815b036d9bbbce5e9f2a00abd1bf3dc91e95510"),
                mainnet,
            ),
            net = mainnet,
        ))

        # Positive P2PK tests.
        tests.append(test(
            name =    "mainnet p2pk compressed (0x02)",
            addr =    "DsT4FDqBKYG1Xr8aGrT1rKP3kiv6TZ5K5th",
            encoded = "DsT4FDqBKYG1Xr8aGrT1rKP3kiv6TZ5K5th",
            valid =   True,
            scriptAddress = ByteArray("028f53838b7639563f27c94845549a41e5146bcd52e7fef0ea6da143a02b0fe2ed"),
            f = lambda: addrPK(
                ByteArray("028f53838b7639563f27c94845549a41e5146bcd52e7fef0ea6da143a02b0fe2ed"),
                mainnet,
            ),
            net = mainnet,
        ))
        tests.append(test(
            name =    "mainnet p2pk compressed (0x03)",
            addr =    "DsfiE2y23CGwKNxSGjbfPGeEW4xw1tamZdc",
            encoded = "DsfiE2y23CGwKNxSGjbfPGeEW4xw1tamZdc",
            valid =   True,
            scriptAddress = ByteArray("03e925aafc1edd44e7c7f1ea4fb7d265dc672f204c3d0c81930389c10b81fb75de"),
            f = lambda: addrPK(
                ByteArray("03e925aafc1edd44e7c7f1ea4fb7d265dc672f204c3d0c81930389c10b81fb75de"),
                mainnet,
            ),
            net = mainnet,
        ))
        tests.append(test(
            name =    "mainnet p2pk uncompressed (0x04)",
            addr =    "DkM3EyZ546GghVSkvzb6J47PvGDyntqiDtFgipQhNj78Xm2mUYRpf",
            encoded = "DsfFjaADsV8c5oHWx85ZqfxCZy74K8RFuhK",
            valid =   True,
            saddr =   "0264c44653d6567eff5753c5d24a682ddc2b2cadfe1b0c6433b16374dace6778f0",
            scriptAddress = ByteArray("0464c44653d6567eff5753c5d24a682ddc2b2cadfe1b0c6433b16374dace6778f0b87ca4279b565d2130ce59f75bfbb2b88da794143d7cfd3e80808a1fa3203904"),
            f = lambda: addrPK(
                ByteArray("0464c44653d6567eff5753c5d24a682ddc2b2cadfe1b0c6433b16374dace6778f0b87ca4279b565d2130ce59f75bfbb2b88da794143d7cfd3e80808a1fa3203904"),
                mainnet,
            ),
            net = mainnet,
        ))
        tests.append(test(
            name =    "testnet p2pk compressed (0x02)",
            addr =    "Tso9sQD3ALqRsmEkAm7KvPrkGbeG2Vun7Kv",
            encoded = "Tso9sQD3ALqRsmEkAm7KvPrkGbeG2Vun7Kv",
            valid =   True,
            scriptAddress = ByteArray("026a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06e"),
            f = lambda: addrPK(
                ByteArray("026a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06e"),
                testnet,
            ),
            net = testnet,
        ))
        tests.append(test(
            name =    "testnet p2pk compressed (0x03)",
            addr =    "TsWZ1EzypJfMwBKAEDYKuyHRGctqGAxMje2",
            encoded = "TsWZ1EzypJfMwBKAEDYKuyHRGctqGAxMje2",
            valid =   True,
            scriptAddress =  ByteArray("030844ee70d8384d5250e9bb3a6a73d4b5bec770e8b31d6a0ae9fb739009d91af5"),
            f = lambda: addrPK(
                ByteArray("030844ee70d8384d5250e9bb3a6a73d4b5bec770e8b31d6a0ae9fb739009d91af5"),
                testnet,
            ),
            net = testnet,
        ))
        tests.append(test(
            name =    "testnet p2pk uncompressed (0x04)",
            addr =    "TkKmMiY5iDh4U3KkSopYgkU1AzhAcQZiSoVhYhFymZHGMi9LM9Fdt",
            encoded = "Tso9sQD3ALqRsmEkAm7KvPrkGbeG2Vun7Kv",
            valid =   True,
            saddr =   "026a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06e",
            scriptAddress = ByteArray("046a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06ed548c8c16fb5eb9007cb94220b3bb89491d5a1fd2d77867fca64217acecf2244"),
            f = lambda: addrPK(
                ByteArray("046a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06ed548c8c16fb5eb9007cb94220b3bb89491d5a1fd2d77867fca64217acecf2244"),
                testnet,
            ),
            net = testnet,
        ))

        # Negative P2PK tests.
        tests.append(test(
            name =  "mainnet p2pk hybrid (0x06)",
            addr =  "",
            valid = False,
            f = lambda: addrPK(
                ByteArray("0664c44653d6567eff5753c5d24a682ddc2b2cadfe1b0c6433b16374dace6778f0b87ca4279b565d2130ce59f75bfbb2b88da794143d7cfd3e80808a1fa3203904"),
                mainnet,
            ),
            net = mainnet,
        ))
        tests.append(test(
            name =  "mainnet p2pk hybrid (0x07)",
            addr =  "",
            valid = False,
            f = lambda: addrPK(
                ByteArray("07348d8aeb4253ca52456fe5da94ab1263bfee16bb8192497f666389ca964f84798375129d7958843b14258b905dc94faed324dd8a9d67ffac8cc0a85be84bac5d"),
                mainnet,
            ),
            net = mainnet,
        ))
        tests.append(test(
            name =  "testnet p2pk hybrid (0x06)",
            addr =  "",
            valid = False,
            f = lambda: addrPK(
                ByteArray("066a40c403e74670c4de7656a09caa2353d4b383a9ce66eef51e1220eacf4be06ed548c8c16fb5eb9007cb94220b3bb89491d5a1fd2d77867fca64217acecf2244"),
                testnet,
            ),
            net = testnet,
        ))
        tests.append(test(
            name =  "testnet p2pk hybrid (0x07)",
            addr =  "",
            valid = False,
            f = lambda: addrPK(
                ByteArray("07edd40747de905a9becb14987a1a26c1adbd617c45e1583c142a635bfda9493dfa1c6d36735974965fe7b861e7f6fcc087dc7fe47380fa8bde0d9c322d53c0e89"),
                testnet,
            ),
            net = testnet,
        ))

        for test in tests:
            # Decode addr and compare error against valid.
            err = None
            try: 
                decoded = decodeAddress(test.addr, test.net)
            except Exception as e:
                err = e
            self.assertEqual(err == None, test.valid, "%s error: %s" % (test.name, err))

            if err == None:
                # Ensure the stringer returns the same address as theoriginal.
                self.assertEqual(test.addr, decoded.string(), test.name)

                # Encode again and compare against the original.
                encoded = decoded.address()
                self.assertEqual(test.encoded, encoded)

                # Perform type-specific calculations.
                if isinstance(decoded, crypto.AddressPubKeyHash):
                    d = ByteArray(b58decode(encoded))
                    saddr = d[2 : 2+crypto.RIPEMD160_SIZE]

                elif isinstance(decoded, crypto.AddressScriptHash):
                    d = ByteArray(b58decode(encoded))
                    saddr = d[2 : 2+crypto.RIPEMD160_SIZE]

                elif isinstance(decoded, crypto.AddressSecpPubKey):
                    # Ignore the error here since the script
                    # address is checked below.
                    try: 
                        saddr = ByteArray(decoded.string())
                    except Exception:
                        saddr = test.saddr

                elif isinstance(decoded, crypto.AddressEdwardsPubKey):
                    # Ignore the error here since the script
                    # address is checked below.
                    # saddr = ByteArray(decoded.String())
                    self.fail("Edwards sigs unsupported")

                elif isinstance(decoded, crypto.AddressSecSchnorrPubKey):
                    # Ignore the error here since the script
                    # address is checked below.
                    # saddr = ByteArray(decoded.String())
                    self.fail("Schnorr sigs unsupported")

                # Check script address, as well as the Hash160 method for P2PKH and
                # P2SH addresses.
                self.assertEqual(saddr, decoded.scriptAddress(), test.name)

                if isinstance(decoded, crypto.AddressPubKeyHash):
                    self.assertEqual(decoded.pkHash, saddr)

                if isinstance(decoded, crypto.AddressScriptHash):
                    self.assertEqual(decoded.hash160(), saddr)

            if not test.valid:
                # If address is invalid, but a creation function exists,
                # verify that it returns a nil addr and non-nil error.
                if test.f != None:
                    try:
                        test.f()
                        self.fail("%s: address is invalid but creating new address succeeded" % test.name)
                    except Exception:
                        pass
                continue

            # Valid test, compare address created with f against expected result.
            try:
                addr = test.f()
            except Exception as e:
                self.fail("%s: address is valid but creating new address failed with error %s", test.name, e)
            self.assertEqual(addr.scriptAddress(), test.scriptAddress, test.name)

    def test_extract_script_addrs(self):
        from tinydecred.pydecred import mainnet
        scriptVersion = 0
        tests = []
        def pkAddr(b):
            addr = crypto.AddressSecpPubKey(b, mainnet)
            # force the format to compressed, as per golang tests.
            addr.pubkeyFormat = crypto.PKFCompressed
            return addr

        class test:
            def __init__(self, name="", script=b'', addrs=None, reqSigs=-1, scriptClass=-1, exception=None):
                self.name = name 
                self.script = script 
                self.addrs = addrs if addrs else []
                self.reqSigs = reqSigs 
                self.scriptClass = scriptClass
                self.exception = exception
        tests.append(test(
            name = "standard p2pk with compressed pubkey (0x02)",
            script = ByteArray("2102192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4ac"),
            addrs = [pkAddr(ByteArray("02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4"))],
            reqSigs = 1,
            scriptClass = PubKeyTy,
        ))
        tests.append(test(
            name = "standard p2pk with uncompressed pubkey (0x04)",
            script = ByteArray("410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddf"
                "b84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"),
            addrs = [
                pkAddr(ByteArray("0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482eca"
                    "d7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3")),
            ],
            reqSigs = 1,
            scriptClass = PubKeyTy,
        ))
        tests.append(test(
            name = "standard p2pk with compressed pubkey (0x03)",
            script = ByteArray("2103b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65ac"),
            addrs = [pkAddr(ByteArray("03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65"))],
            reqSigs = 1,
            scriptClass = PubKeyTy,
        ))
        tests.append(test(
            name = "2nd standard p2pk with uncompressed pubkey (0x04)",
            script = ByteArray("4104b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782"
                "eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7bac"),
            addrs = [
                pkAddr(ByteArray("04b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2"
                    "c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b")),
            ],
            reqSigs = 1,
            scriptClass = PubKeyTy,
        ))
        tests.append(test(
            name = "standard p2pkh",
            script = ByteArray("76a914ad06dd6ddee55cbca9a9e3713bd7587509a3056488ac"),
            addrs = [crypto.newAddressPubKeyHash(ByteArray("ad06dd6ddee55cbca9a9e3713bd7587509a30564"), mainnet, crypto.STEcdsaSecp256k1)],
            reqSigs = 1,
            scriptClass = PubKeyHashTy,
        ))
        tests.append(test(
            name = "standard p2sh",
            script = ByteArray("a91463bcc565f9e68ee0189dd5cc67f1b0e5f02f45cb87"),
            addrs = [crypto.newAddressScriptHashFromHash(ByteArray("63bcc565f9e68ee0189dd5cc67f1b0e5f02f45cb"), mainnet)],
            reqSigs = 1,
            scriptClass = ScriptHashTy,
        ))
        # from real tx 60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1, vout 0
        tests.append(test(
            name = "standard 1 of 2 multisig",
            script = ByteArray("514104cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a47"
                "3e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4410461cbdcc5409fb4b4d42b51d3338"
                "1354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af52ae"),
            addrs = [
                pkAddr(ByteArray("04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a"
                    "1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4")),
                pkAddr(ByteArray("0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34b"
                    "fa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af")),
            ],
            reqSigs = 1,
            scriptClass = MultiSigTy,
        ))
        # from real tx d646f82bd5fbdb94a36872ce460f97662b80c3050ad3209bef9d1e398ea277ab, vin 1
        tests.append(test(
            name = "standard 2 of 3 multisig",
            script = ByteArray("524104cb9c3c222c5f7a7d3b9bd152f363a0b6d54c9eb312c4d4f9af1e8551b6c421a6a4ab0e2"
                "9105f24de20ff463c1c91fcf3bf662cdde4783d4799f787cb7c08869b4104ccc588420deeebea22a7e900cc8"
                "b68620d2212c374604e3487ca08f1ff3ae12bdc639514d0ec8612a2d3c519f084d9a00cbbe3b53d071e9b09e"
                "71e610b036aa24104ab47ad1939edcb3db65f7fedea62bbf781c5410d3f22a7a3a56ffefb2238af8627363bd"
                "f2ed97c1f89784a1aecdb43384f11d2acc64443c7fc299cef0400421a53ae"),
            addrs = [
                pkAddr(ByteArray("04cb9c3c222c5f7a7d3b9bd152f363a0b6d54c9eb312c4d4f9af"
                    "1e8551b6c421a6a4ab0e29105f24de20ff463c1c91fcf3bf662cdde4783d4799f787cb7c08869b")),
                pkAddr(ByteArray("04ccc588420deeebea22a7e900cc8b68620d2212c374604e3487"
                    "ca08f1ff3ae12bdc639514d0ec8612a2d3c519f084d9a00cbbe3b53d071e9b09e71e610b036aa2")),
                pkAddr(ByteArray("04ab47ad1939edcb3db65f7fedea62bbf781c5410d3f22a7a3a5"
                    "6ffefb2238af8627363bdf2ed97c1f89784a1aecdb43384f11d2acc64443c7fc299cef0400421a")),
            ],
            reqSigs = 2,
            scriptClass = MultiSigTy,
        ))

        # The below are nonstandard script due to things such as
        # invalid pubkeys, failure to parse, and not being of a
        # standard form.

        tests.append(test(
            name = "p2pk with uncompressed pk missing OP_CHECKSIG",
            script = ByteArray("410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddf"
                "b84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"),
            addrs =   [],
            exception = "unsupported script",
        ))
        tests.append(test(
            name = "valid signature from a sigscript - no addresses",
            script = ByteArray("47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41022"
                "0181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901"),
            addrs =   [],
            exception = "unsupported script",
        ))
        # Note the technically the pubkey is the second item on the
        # stack, but since the address extraction intentionally only
        # works with standard PkScripts, this should not return any
        # addresses.
        tests.append(test(
            name = "valid sigscript to redeem p2pk - no addresses",
            script = ByteArray("493046022100ddc69738bf2336318e4e041a5a77f305da87428ab1606f023260017854350ddc0"
                "22100817af09d2eec36862d16009852b7e3a0f6dd76598290b7834e1453660367e07a014104cd4240c198e12"
                "523b6f9cb9f5bed06de1ba37e96a1bbd13745fcf9d11c25b1dff9a519675d198804ba9962d3eca2d5937d58e5a75a71042d40388a4d307f887d"),
            addrs =   [],
            reqSigs = 0,
            exception = "unsupported script",
        ))
        # adapted from btc:
        # tx 691dd277dc0e90a462a3d652a1171686de49cf19067cd33c7df0392833fb986a, vout 0
        # invalid public keys
        tests.append(test(
            name = "1 of 3 multisig with invalid pubkeys",
            script = ByteArray("5141042200007353455857696b696c65616b73204361626c6567617465204261636b75700a0a6"
                "361626c65676174652d3230313031323034313831312e377a0a0a446f41046e6c6f61642074686520666f6c6"
                "c6f77696e67207472616e73616374696f6e732077697468205361746f736869204e616b616d6f746f2773206"
                "46f776e6c6f61410420746f6f6c2077686963680a63616e20626520666f756e6420696e207472616e7361637"
                "4696f6e2036633533636439383731313965663739376435616463636453ae"),
            addrs =   [],
            exception = "isn't on secp256k1 curve",
        ))
        # adapted from btc:
        # tx 691dd277dc0e90a462a3d652a1171686de49cf19067cd33c7df0392833fb986a, vout 44
        # invalid public keys
        tests.append(test(
            name = "1 of 3 multisig with invalid pubkeys 2",
            script = ByteArray("514104633365633235396337346461636536666430383862343463656638630a6336366263313"
                "9393663386239346133383131623336353631386665316539623162354104636163636539393361333938386"
                "134363966636336643664616266640a323636336366613963663463303363363039633539336333653931666"
                "56465373032392102323364643432643235363339643338613663663530616234636434340a00000053ae"),
            addrs =   [],
            exception = "isn't on secp256k1 curve",
        ))
        tests.append(test(
            name =    "empty script",
            script =  ByteArray(b''),
            addrs =   [],
            reqSigs = 0,
            exception = "unsupported script",
        ))
        tests.append(test(
            name = "script that does not parse",
            script =  ByteArray([opcode.OP_DATA_45]),
            addrs =   [],
            reqSigs = 0,
            exception = "unsupported script",
        ))

        def checkAddrs(a, b, name):
            if len(a) != len(b):
                t.fail("extracted address length mismatch. expected %d, got %d" % (len(a), len(b)))
            for av, bv in zip(a, b):
                if av.scriptAddress() != bv.scriptAddress():
                    self.fail("scriptAddress mismatch. expected %s, got %s (%s)" % 
                        (av.scriptAddress().hex(), bv.scriptAddress().hex(), name))

        for i, t in enumerate(tests):
            try: 
                scriptClass, addrs, reqSigs = extractPkScriptAddrs(scriptVersion, t.script, mainnet)
            except Exception as e:
                if t.exception and t.exception in str(e):
                    continue
                self.fail("extractPkScriptAddrs #%d (%s): %s" % (i, t.name, e))

            self.assertEqual(scriptClass, t.scriptClass, t.name)

            self.assertEqual(reqSigs, t.reqSigs, t.name)

            checkAddrs(t.addrs, addrs, t.name)
