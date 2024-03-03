package x509

import (
    "hash"
    "strconv"
    "crypto"
    "crypto/cipher"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"

    "golang.org/x/crypto/sha3"
    "golang.org/x/crypto/blake2s"
    "golang.org/x/crypto/blake2b"
    "golang.org/x/crypto/ripemd160"

    "github.com/deatil/go-cryptobin/hash/sm3"

    cipher_gost "github.com/deatil/go-cryptobin/cipher/gost"
    "github.com/deatil/go-cryptobin/hash/gost/gost341194"
    "github.com/deatil/go-cryptobin/hash/gost/gost34112012256"
    "github.com/deatil/go-cryptobin/hash/gost/gost34112012512"
)

type Hash uint

// HashFunc simply returns the value of h so that Hash implements SignerOpts.
func (h Hash) HashFunc() crypto.Hash {
    return crypto.Hash(h)
}

func (h Hash) String() string {
    switch h {
    case MD4:
        return "MD4"
    case MD5:
        return "MD5"
    case SHA1:
        return "SHA-1"
    case SHA224:
        return "SHA-224"
    case SHA256:
        return "SHA-256"
    case SHA384:
        return "SHA-384"
    case SHA512:
        return "SHA-512"
    case MD5SHA1:
        return "MD5+SHA1"
    case RIPEMD160:
        return "RIPEMD-160"
    case SHA3_224:
        return "SHA3-224"
    case SHA3_256:
        return "SHA3-256"
    case SHA3_384:
        return "SHA3-384"
    case SHA3_512:
        return "SHA3-512"
    case SHA512_224:
        return "SHA-512/224"
    case SHA512_256:
        return "SHA-512/256"
    case BLAKE2s_256:
        return "BLAKE2s-256"
    case BLAKE2b_256:
        return "BLAKE2b-256"
    case BLAKE2b_384:
        return "BLAKE2b-384"
    case BLAKE2b_512:
        return "BLAKE2b-512"
    case SM3:
        return "SM3"
    case GOST34112001:
        return "GOST34112001"
    case GOST34112012256:
        return "GOST34112012256"
    case GOST34112012512:
        return "GOST34112012512"
    default:
        return "unknown hash value " + strconv.Itoa(int(h))
    }
}

const (
    MD4        Hash = 1 + iota // import golang.org/x/crypto/md4
    MD5                        // import crypto/md5
    SHA1                       // import crypto/sha1
    SHA224                     // import crypto/sha256
    SHA256                     // import crypto/sha256
    SHA384                     // import crypto/sha512
    SHA512                     // import crypto/sha512
    MD5SHA1                    // no implementation; MD5+SHA1 used for TLS RSA
    RIPEMD160                  // import golang.org/x/crypto/ripemd160
    SHA3_224                   // import golang.org/x/crypto/sha3
    SHA3_256                   // import golang.org/x/crypto/sha3
    SHA3_384                   // import golang.org/x/crypto/sha3
    SHA3_512                   // import golang.org/x/crypto/sha3
    SHA512_224                 // import crypto/sha512
    SHA512_256                 // import crypto/sha512
    BLAKE2s_256                 // import golang.org/x/crypto/blake2s
    BLAKE2b_256                 // import golang.org/x/crypto/blake2b
    BLAKE2b_384                 // import golang.org/x/crypto/blake2b
    BLAKE2b_512                 // import golang.org/x/crypto/blake2b
    SM3
    GOST34112001
    GOST34112012256
    GOST34112012512
    maxHash
)

var digestSizes = []uint8{
    MD4:         16,
    MD5:         16,
    SHA1:        20,
    SHA224:      28,
    SHA256:      32,
    SHA384:      48,
    SHA512:      64,
    SHA512_224:  28,
    SHA512_256:  32,
    SHA3_224:    28,
    SHA3_256:    32,
    SHA3_384:    48,
    SHA3_512:    64,
    MD5SHA1:     36,
    RIPEMD160:   20,
    BLAKE2s_256: 32,
    BLAKE2b_256: 32,
    BLAKE2b_384: 48,
    BLAKE2b_512: 64,
    SM3:         32,
    GOST34112001:    32,
    GOST34112012256: 32,
    GOST34112012512: 64,
}

// Size returns the length, in bytes, of a digest resulting from the given hash
// function. It doesn't require that the hash function in question be linked
// into the program.
func (h Hash) Size() int {
    if h > 0 && h < maxHash {
        return int(digestSizes[h])
    }

    panic("crypto: Size of unknown hash function")
}

// New returns a new hash.Hash calculating the given hash function. New panics
// if the hash function is not linked into the binary.
func (h Hash) New() hash.Hash {
    if h > 0 && h < maxHash {
        f := hashes[h]
        if f != nil {
            return f()
        }
    }

    panic("crypto: requested hash function #" + strconv.Itoa(int(h)) + " is unavailable")
}

// Available reports whether the given hash function is linked into the binary.
func (h Hash) Available() bool {
    return h < maxHash && hashes[h] != nil
}

var hashes = make([]func() hash.Hash, maxHash)

// RegisterHash registers a function that returns a new instance of the given
// hash function. This is intended to be called from the init function in
// packages that implement hash functions.
func RegisterHash(h Hash, f func() hash.Hash) {
    if h >= maxHash {
        panic("crypto: RegisterHash of unknown hash function")
    }
    hashes[h] = f
}

var (
    newHashBlake2s_256 = func() hash.Hash {
        h, _ := blake2s.New256(nil)
        return h
    }
    newHashBlake2b_256 = func() hash.Hash {
        h, _ := blake2b.New256(nil)
        return h
    }
    newHashBlake2b_384 = func() hash.Hash {
        h, _ := blake2b.New384(nil)
        return h
    }
    newHashBlake2b_512 = func() hash.Hash {
        h, _ := blake2b.New512(nil)
        return h
    }

    newHashGOST34112001 = func() hash.Hash {
        return gost341194.New(func(key []byte) cipher.Block {
            cip, _ := cipher_gost.NewCipher(key, cipher_gost.SboxGostR341194CryptoProParamSet)

            return cip
        })
    }
)

func init() {
    RegisterHash(MD4, nil)
    RegisterHash(MD5, md5.New)
    RegisterHash(SHA1, sha1.New)
    RegisterHash(SHA224, sha256.New224)
    RegisterHash(SHA256, sha256.New)
    RegisterHash(SHA384, sha512.New384)
    RegisterHash(SHA512, sha512.New)
    RegisterHash(MD5SHA1, nil)
    RegisterHash(RIPEMD160, ripemd160.New)
    RegisterHash(SHA3_224, sha3.New224)
    RegisterHash(SHA3_256, sha3.New256)
    RegisterHash(SHA3_384, sha3.New384)
    RegisterHash(SHA3_512, sha3.New512)
    RegisterHash(SHA512_224, sha512.New512_224)
    RegisterHash(SHA512_256, sha512.New512_256)

    RegisterHash(BLAKE2s_256, newHashBlake2s_256)
    RegisterHash(BLAKE2b_256, newHashBlake2b_256)
    RegisterHash(BLAKE2b_384, newHashBlake2b_384)
    RegisterHash(BLAKE2b_512, newHashBlake2b_512)

    RegisterHash(SM3, sm3.New)
    RegisterHash(GOST34112001, newHashGOST34112001)
    RegisterHash(GOST34112012256, gost34112012256.New)
    RegisterHash(GOST34112012512, gost34112012512.New)
}
