import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256
from Crypto.Random import random
import scrypt
import binascii
import ecdsa # github.com/warner/python-ecdsa

# Crypto/encoding related to Bitcoin keypairs
# Incomplete, contains pseudocode, and is largely untested

# TODO: Credit various authors of original code
# TODO: Verify Crypto.Random is cryptographically secure
# TODO: Improve uniformity, check for redundancy
# TODO: hashlib.sha256 vs Crypto.Hash.SHA256
# TODO: Document/README

# AES (non-standard encryption)
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

# base58 constants
__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

# BEGIN non-standard encryption (testing)

def AESencrypt(plaintext, passphrase):
    raw = pad(plaintext)
    key = hashlib.sha256(passphrase).digest()
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

def AESdecrypt(encrypted, passphrase):
    encrypted = base64.b64decode(encrypted)
    key = hashlib.sha256(passphrase).digest()
    # Determine IV
    iv = encrypted[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted[16:]))

def ARC4encrypt(plaintext, passphrase):
    key = hashlib.sha256(passphrase).digest()
    enc = ARC4.new(key)
    return base64.b64encode(enc.encrypt(plaintext))

def ARC4decrypt(encrypted, passphrase):
    encrypted = base64.b64decode(encrypted)
    key = hashlib.sha256(passphrase).digest()
    dec = ARC4.new(key)
    return dec.decrypt(encrypted)

# END non-standard encryption
# BEGIN b58

def b58encode(v):
    """ encode v, which is a string of bytes, to base58.
    """

    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0': nPad += 1
        else: break

    return (__b58chars[0]*nPad) + result

def b58decode(v, length):
    """ decode v into a string of len bytes
    """
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base**i)

    result = ''
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]: nPad += 1
        else: break

    result = chr(0)*nPad + result
    if length is not None and len(result) != length:
        return None

    return result

def get_bcaddress_version(strAddress):
    """ Returns None if strAddress is invalid.  Otherwise returns integer version of address. """
    addr = b58decode(strAddress,25)
    if addr is None: return None
    version = addr[0]
    checksum = addr[-4:]
    vh160 = addr[:-4] # Version plus hash160 is what is checksummed
    h3=SHA256.new(SHA256.new(vh160).digest()).digest()
    if h3[0:4] == checksum:
        return ord(version)
    return None

# END b58
# BEGIN BIP 0038 - https://en.bitcoin.it/wiki/BIP_0038

def BIP38_intermediate():
    # Generate 4 random bytes
    ownersalt = os.urandom(4)
    # lotnumber chosen at random in range 100000-999999
    lotnumber = int(random.randint(100000,999999))
    # sequence numbers increment from 1
    sequencenumber = 1
    # Encode the lot and sequence numbers as a 
    # 4 byte quantity (big-endian):
    # lotsequence = lotnumber * 4096 + sequencenumber
    ## NOTE: check lotsequence math
    lotsequence = lotnumber * 4096 + sequencenumber
    # Concatenate ownersalt + lotsequence and call this ownerentropy.
    ownerentropy = ownersalt + lotsequence
    # Derive a key from the passphrase using scrypt
    # passphrase is UTF-8. salt is ownersalt. n=16384, r=8, p=8, length=32
    prefactor = scrypt(passphrase=userpass,salt=ownersalt,n=16384,r=8,p=8,length=32)
    # Take SHA256(SHA256(prefactor + ownerentropy)) and call this passfactor.
    passfactor = SHA256(SHA256(prefactor + ownerentropy))
    # Compute the elliptic curve point G * passfactor, convert the result to compressed notation (33 bytes)
    # TODO: math, compressed notation
    passpoint = mathgoeshere
    pass
    
##    Convey ownersalt and passpoint to the party generating the keys, along with a checksum to ensure integrity.
##    The following Base58Check-encoded format is recommended for this purpose:
##    magic bytes "2C E9 B3 E1 FF 39 E2 51" followed by ownerentropy, and then passpoint.
##    The resulting string will start with the word "passphrase" due to the constant bytes,
##    will be 72 characters in length, and encodes 49 bytes
##    (8 bytes constant + 8 bytes ownersalt + 33 bytes passpoint).
##    The checksum is handled in the Base58Check encoding.
##    The resulting string is called intermediate_passphrase_string.

##    If lot and sequence numbers are not being included, follow the same procedure with following changes:
##    ownersalt is 8 random bytes instead of 4,
##    and lotsequence is omitted. ownerentropy becomes an alias for ownersalt.
##    The SHA256 conversion of prefactor to passfactor is omitted.
##    Instead, the output of scrypt is used directly as passfactor.
##    The magic bytes are "2C E9 B3 E1 FF 39 E2 53" instead (the last byte is 0x53 instead of 0x51).
##    Steps to create new encrypted private keys given intermediate_passphrase_string from owner
##    (so we have ownerentropy, and passpoint, but we do not have passfactor or the passphrase):

def BIP38encrypt(WIFkey,passphrase):
    """
    BIP0038 encrypt a wallet import format privatekey without EC multiplication
    """
    ##Compute the Bitcoin address (ASCII),
    address = address_from_privkey.determine_address(WIFkey)
    ##take the first four bytes of SHA256(SHA256()) of it. Let's call this "addresshash".
    addresshash = SHA256(SHA256(address))
    addresshash = addresshash[:4]
    ##Derive a key from the passphrase using scrypt
    ##Parameters: passphrase is the passphrase itself encoded in UTF-8. (salt is addresshash)
    ##addresshash, n=16384, r=8, p=8, length=64 (n, r, p are provisional and subject to consensus)
    # scrypt.hash('password','random salt')
    key = scrypt.hash(passphrase, addresshash, n=16384, r=8, p=8, length=64)
    ##Let's split the resulting 64 bytes in half, and call them derivedhalf1 and derivedhalf2.
    derivedhalf1 = key[:31]
    derivedhalf2 = key[32:]
    ##Do AES256Encrypt(bitcoinprivkey[0...15] xor derivedhalf1[0...15], derivedhalf2), call the 16-byte result encryptedhalf1
    #encryptedhalf1 = AES256encrypt(WIFprivkey[:15] xor derivedhalf1[:15],derivedhalf2)
    ##Do AES256Encrypt(bitcoinprivkey[16...31] xor derivedhalf1[16...31], derivedhalf2), call the 16-byte result encryptedhalf2
    #encryptedhalf2 = AES256encrypt(WIFprivkey[16:] xor derivedhalf1[16:],derivedhalf2)
    ##The encrypted private key is the Base58Check-encoded concatenation of the following,
    ##which totals 39 bytes without Base58 checksum:
    ##0x01 0x42 + flagbyte + salt + encryptedhalf1 + encryptedhalf2
    return b58encode(0x01+0x42+flagbyte+salt+encryptedhalf1+encryptedhalf2)

def BIP38encrypt_EC(WIFkey,passphrase):
    """
    BIP0038 encrypt a WIF private key with EC multiplication
    """
    pass

def BIP38decrypt(WIFkey,passphrase):
    """
    BIP0038 decryption without EC multiplication
    """
    pass

def BIP38decrypt_EC(WIFkey,passphrase):
    """
    BIP0038 decryption with EC multiplication
    """
    pass

## END BIP0038
## BEGIN Mini Private Key
## NOTE: depends on BASE58, which differs from __b58chars for reasons unknown
 
def Candidate():
    """
    Generate a random, well-formed mini private key.
    """
    return('%s%s' % ('S', ''.join(
        [BASE58[ random.randrange(0,len(BASE58)) ] for i in range(29)])))
 
def GenerateKeys(numKeys = 10):
    """
    Generate mini private keys and output the mini key as well as the full
    private key. numKeys is The number of keys to generate, and 
    """
    keysGenerated = 0
    totalCandidates = 0
    while keysGenerated < numKeys:
        try:
            cand = Candidate()
            # Do typo check
            t = '%s?' % cand
            # Take one round of SHA256
            candHash = hashlib.sha256(t).digest()
            # Check if the first eight bits of the hash are 0
            if candHash[0] == '\x00':
                privateKey = GetPrivateKey(cand)
                print('\n%s\nSHA256( ): %s\nsha256(?): %s' %
                      (cand, privateKey, candHash.encode('hex_codec')))
                if CheckShortKey(cand):
                    print('Validated.')
                else:
                    print('Invalid!')
                keysGenerated += 1
            totalCandidates += 1
        except KeyboardInterrupt:
            break
    print('\n%s: %i\n%s: %i\n%s: %.1f' %
          ('Keys Generated', keysGenerated,
           'Total Candidates', totalCandidates,
           'Reject Percentage',
           100*(1.0-keysGenerated/float(totalCandidates))))
 
def GetPrivateKey(shortKey):
    """
    Returns the hexadecimal representation of the private key corresponding
    to the given short key.
    """
    if CheckShortKey(shortKey):
        return hashlib.sha256(shortKey).hexdigest()
    else:
        print('Typo detected in private key!')
        return None
 
def CheckShortKey(shortKey):
    """
    Checks for typos in the short key.
    """
    if len(shortKey) != 30:
        return False
    t = '%s?' % shortKey
    tHash = hashlib.sha256(t).digest()
    # Check to see that first byte is \x00
    if tHash[0] == '\x00':
        return True
    return False

## END Mini private key

## BEGIN Address from privkey
# Code originally from JeromeS - https://bitcointalk.org/index.php?topic=84238

secp256k1curve=ecdsa.ellipticcurve.CurveFp(115792089237316195423570985008687907853269984665640564039457584007908834671663,0,7)
secp256k1point=ecdsa.ellipticcurve.Point(secp256k1curve,0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
secp256k1=ecdsa.curves.Curve('secp256k1',secp256k1curve,secp256k1point,(1,3,132,0,10))

def determine_address(pk):
 pko=ecdsa.SigningKey.from_secret_exponent(pk,secp256k1)
 pubkey=binascii.hexlify(pko.get_verifying_key().to_string())
 pubkey2=hashlib.sha256(binascii.unhexlify('04'+pubkey)).hexdigest()
 pubkey3=hashlib.new('ripemd160',binascii.unhexlify(pubkey2)).hexdigest()
 pubkey4=hashlib.sha256(binascii.unhexlify('00'+pubkey3)).hexdigest()
 pubkey5=hashlib.sha256(binascii.unhexlify(pubkey4)).hexdigest()
 pubkey6=pubkey3+pubkey5[:8]
 pubnum=int(pubkey6,16)
 pubnumlist=[]
 while pubnum!=0: pubnumlist.append(pubnum%58); pubnum/=58
 address=''
 for l in [__b58chars[x] for x in pubnumlist]:
  address=l+address
 return '1'+address

def num_to_wif(numpriv):
 step1 = '80'+hex(numpriv)[2:].strip('L').zfill(64)
 step2 = hashlib.sha256(binascii.unhexlify(step1)).hexdigest()
 step3 = hashlib.sha256(binascii.unhexlify(step2)).hexdigest()
 step4 = int(step1 + step3[:8] , 16)
 return ''.join([__b58chars[step4/(58**l)%58] for l in range(100)])[::-1].lstrip('1')

def wif_to_num(wifpriv):
 return sum([__b58chars.index(wifpriv[::-1][l])*(58**l) for l in range(len(wifpriv))])/(2**32)%(2**256)

def valid_wif(wifpriv):
 return num_to_wif(wif_to_num(wifpriv)) == wifpriv
