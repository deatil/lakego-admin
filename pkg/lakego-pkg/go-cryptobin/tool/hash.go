package tool

import (
    "hash"
    "crypto"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"

    "golang.org/x/crypto/md4"
    "golang.org/x/crypto/sha3"
    "golang.org/x/crypto/blake2s"
    "golang.org/x/crypto/blake2b"
    "golang.org/x/crypto/ripemd160"

    "github.com/tjfoc/gmsm/sm3"
)

type (
    // hashFunc
    hashFunc = func() hash.Hash

    // hash
    HashMap = map[string]hashFunc

    // hash
    CryptoHashMap = map[string]crypto.Hash
)

var (
    newBlake2sHash256 = func() hash.Hash {
        h, _ := blake2s.New256(nil)
        return h
    }
    newBlake2bHash256 = func() hash.Hash {
        h, _ := blake2b.New256(nil)
        return h
    }
    newBlake2bHash384 = func() hash.Hash {
        h, _ := blake2b.New384(nil)
        return h
    }
    newBlake2bHash512 = func() hash.Hash {
        h, _ := blake2b.New512(nil)
        return h
    }
)

// 默认列表
var defaultHashes = HashMap{
    "MD4": md4.New,
    "MD5": md5.New,
    "SHA1": sha1.New,
    "SHA224": sha256.New224,
    "SHA256": sha256.New,
    "SHA384": sha512.New384,
    "SHA512": sha512.New,
    "RIPEMD160": ripemd160.New,
    "SHA3_224": sha3.New224,
    "SHA3_256": sha3.New256,
    "SHA3_384": sha3.New384,
    "SHA3_512": sha3.New512,
    "SHA512_224": sha512.New512_224,
    "SHA512_256": sha512.New512_256,
    "BLAKE2s_256": newBlake2sHash256,
    "BLAKE2b_256": newBlake2bHash256,
    "BLAKE2b_384": newBlake2bHash384,
    "BLAKE2b_512": newBlake2bHash512,
    "SM3": sm3.New,
}

// hash 官方默认
var defaultCryptoHashes = CryptoHashMap{
    "MD4": crypto.MD4,
    "MD5": crypto.MD5,
    "SHA1": crypto.SHA1,
    "SHA224": crypto.SHA224,
    "SHA256": crypto.SHA256,
    "SHA384": crypto.SHA384,
    "SHA512": crypto.SHA512,
    "RIPEMD160": crypto.RIPEMD160,
    "SHA3_224": crypto.SHA3_224,
    "SHA3_256": crypto.SHA3_256,
    "SHA3_384": crypto.SHA3_384,
    "SHA3_512": crypto.SHA3_512,
    "SHA512_224": crypto.SHA512_224,
    "SHA512_256": crypto.SHA512_256,
    "BLAKE2s_256": crypto.BLAKE2s_256,
    "BLAKE2b_256": crypto.BLAKE2b_256,
    "BLAKE2b_384": crypto.BLAKE2b_384,
    "BLAKE2b_512": crypto.BLAKE2b_512,
}

/**
 * 摘要
 *
 * @create 2022-4-16
 * @author deatil
 */
type Hash struct {
    // hash 列表
    hashes HashMap

    // hash 官方列表
    cryptoHashes CryptoHashMap
}

// 覆盖 hashes
func (this Hash) WithHashs(hashes HashMap) Hash {
    this.hashes = hashes

    return this
}

// 覆盖 cryptoHashes
func (this Hash) WithCryptoHashs(hashes CryptoHashMap) Hash {
    this.cryptoHashes = hashes

    return this
}

// 添加
func (this Hash) AddHash(name string, sha hashFunc) Hash {
    this.hashes[name] = sha

    return this
}

// 添加
func (this Hash) AddCryptoHash(name string, sha crypto.Hash) Hash {
    this.cryptoHashes[name] = sha

    return this
}

// 类型
func (this Hash) GetHash(typ string) hashFunc {
    sha, ok := this.hashes[typ]
    if ok {
        return sha
    }

    return this.hashes["SHA256"]
}

// 类型
func (this Hash) GetCryptoHash(typ string) crypto.Hash {
    sha, ok := this.cryptoHashes[typ]
    if ok {
        return sha
    }

    return this.cryptoHashes["SHA256"]
}

// 签名后数据
func (this Hash) DataHash(typ string, slices ...[]byte) []byte {
    sha := this.GetHash(typ)

    f := sha()
    for _, slice := range slices {
        f.Write(slice)
    }

    return f.Sum(nil)
}

// 签名后数据
func (this Hash) DataCryptoHash(typ string, slices ...[]byte) []byte {
    sha := this.GetCryptoHash(typ)

    f := sha.New()
    for _, slice := range slices {
        f.Write(slice)
    }

    return f.Sum(nil)
}

// 构造函数
func NewHash() Hash {
    sha := Hash{
        hashes: defaultHashes,
        cryptoHashes: defaultCryptoHashes,
    }

    return sha
}
