package hash

import (
    "strconv"
    "hash"
    "hash/adler32"
    "crypto/md5"
    "crypto/sha1"
    "crypto/hmac"
    "crypto/sha256"
    "crypto/sha512"

    "golang.org/x/crypto/md4"
    "golang.org/x/crypto/sha3"
    "golang.org/x/crypto/ripemd160"
    "github.com/deatil/go-hash/md2"
)

var (
    newAdler32 = func() hash.Hash {
        return adler32.New()
    }
)

func init() {
    RegisterHmacHash(HmacADLER32, newAdler32)
    RegisterHmacHash(HmacMD2, md2.New)
    RegisterHmacHash(HmacMD4, md4.New)
    RegisterHmacHash(HmacMD5, md5.New)
    RegisterHmacHash(HmacSHA1, sha1.New)
    RegisterHmacHash(HmacSHA224, sha256.New224)
    RegisterHmacHash(HmacSHA256, sha256.New)
    RegisterHmacHash(HmacSHA384, sha512.New384)
    RegisterHmacHash(HmacSHA512, sha512.New)
    RegisterHmacHash(HmacSHA512_224, sha512.New512_224)
    RegisterHmacHash(HmacSHA512_256, sha512.New512_256)
    RegisterHmacHash(HmacSHA3_224, sha3.New224)
    RegisterHmacHash(HmacSHA3_256, sha3.New256)
    RegisterHmacHash(HmacSHA3_384, sha3.New384)
    RegisterHmacHash(HmacSHA3_512, sha3.New512)
    RegisterHmacHash(HmacRIPEMD160, ripemd160.New)
}

// hmac 用到的 hash
type HmacHash uint

const (
    HmacADLER32 HmacHash = 1 + iota
    HmacMD2
    HmacMD4
    HmacMD5
    HmacSHA1
    HmacSHA224
    HmacSHA256
    HmacSHA384
    HmacSHA512
    HmacSHA512_224
    HmacSHA512_256
    HmacSHA3_224
    HmacSHA3_256
    HmacSHA3_384
    HmacSHA3_512
    HmacRIPEMD160
)

var hmacHashes = make(map[HmacHash]func() hash.Hash)

func (h HmacHash) New() hash.Hash {
    f := hmacHashes[h]
    if f != nil {
        return f()
    }

    panic("crypto: requested hash function #" + strconv.Itoa(int(h)) + " is unavailable")
}

func RegisterHmacHash(h HmacHash, f func() hash.Hash) {
    hmacHashes[h] = f
}

// Hmac
// HMAC (Hash-based Message Authentication Code) 常用于接口签名验证
// 支持的算法有:
// md5、sha1、sha256、sha512、adler32、crc32、crc32b、crc32c、
// fnv132、fnv164、fnv1a32、fnv1a64、
// gost、gost-crypto、haval128,3、haval128,4、haval128,5、
// haval160,3、haval160,4、haval160,5、haval192,3、haval192,4、
// haval192,5、haval224,3、haval224,4、haval224,5、haval256,3、
// haval256,4、haval256,5、joaat、md2、md4、
// ripemd128、ripemd160、ripemd256、ripemd320、
// sha224、sha3-224、sha3-256、sha3-384、sha3-512、
// sha384、sha512/224、sha512/256、
// snefru、snefru256、tiger128,3、tiger128,4、tiger160,3、
// tiger160,4、tiger192,3、tiger192,4、whirlpool
func (this Hash) Hmac(h func() hash.Hash, secret []byte) Hash {
    mac := hmac.New(h, secret)
    mac.Write(this.data)

    this.data = mac.Sum(nil)

    return this
}

// NewHmac
func (this Hash) NewHmac(h func() hash.Hash, secret []byte) Hash {
    this.hash = hmac.New(h, secret)

    return this
}
