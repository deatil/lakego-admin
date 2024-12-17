package hash

import (
    "hash"
    "errors"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"

    "golang.org/x/crypto/md4"
    "golang.org/x/crypto/sha3"
    "golang.org/x/crypto/blake2s"
    "golang.org/x/crypto/blake2b"
    "golang.org/x/crypto/ripemd160"

    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/hash/md2"
    "github.com/deatil/go-cryptobin/hash/gost/gost34112012256"
    "github.com/deatil/go-cryptobin/hash/gost/gost34112012512"
)

var (
    newBlake2s_256 = func() hash.Hash {
        h, _ := blake2s.New256(nil)
        return h
    }
    newBlake2b_256 = func() hash.Hash {
        h, _ := blake2b.New256(nil)
        return h
    }
    newBlake2b_384 = func() hash.Hash {
        h, _ := blake2b.New384(nil)
        return h
    }
    newBlake2b_512 = func() hash.Hash {
        h, _ := blake2b.New512(nil)
        return h
    }
)

type HashFunc = func() hash.Hash

// 摘要函数列表
var funcHashes = map[string]HashFunc{
    "MD2":         md2.New,
    "MD4":         md4.New,
    "MD5":         md5.New,
    "SHA1":        sha1.New,
    "SHA224":      sha256.New224,
    "SHA256":      sha256.New,
    "SHA384":      sha512.New384,
    "SHA512":      sha512.New,
    "RIPEMD160":   ripemd160.New,
    "SHA3_224":    sha3.New224,
    "SHA3_256":    sha3.New256,
    "SHA3_384":    sha3.New384,
    "SHA3_512":    sha3.New512,
    "SHA512_224":  sha512.New512_224,
    "SHA512_256":  sha512.New512_256,
    "BLAKE2s_256": newBlake2s_256,
    "BLAKE2b_256": newBlake2b_256,
    "BLAKE2b_384": newBlake2b_384,
    "BLAKE2b_512": newBlake2b_512,
    "SM3":         sm3.New,

    "GOST34112012256": gost34112012256.New,
    "GOST34112012512": gost34112012512.New,
}

// 默认
var defaultHash = New()

/**
 * 摘要
 *
 * @create 2022-4-16
 * @author deatil
 */
type Hash struct {
    // hash 列表
    hashes map[string]HashFunc
}

// 构造函数
func New() *Hash {
    sha := &Hash{}
    sha.hashes = funcHashes

    return sha
}

// 添加
func (this *Hash) AddHash(name string, h HashFunc) *Hash {
    this.hashes[name] = h

    return this
}

func AddHash(name string, h HashFunc) *Hash {
    return defaultHash.AddHash(name, h)
}

// 类型
func (this *Hash) GetHash(typ string) (HashFunc, error) {
    if h, ok := this.hashes[typ]; ok {
        return h, nil
    }

    return nil, errors.New("hash type is not support")
}

func GetHash(typ string) (HashFunc, error) {
    return defaultHash.GetHash(typ)
}

// 签名后数据
func (this *Hash) Sum(typ string, slices ...[]byte) ([]byte, error) {
    fn, err := this.GetHash(typ)
    if err != nil {
        return nil, err
    }

    h := fn()
    for _, slice := range slices {
        h.Write(slice)
    }

    return h.Sum(nil), nil
}

func HashSum(typ string, slices ...[]byte) ([]byte, error) {
    return defaultHash.Sum(typ, slices...)
}

// 列席名称列表
func (this *Hash) Names() []string {
    names := make([]string, 0)
    for name, _ := range this.hashes {
        names = append(names, name)
    }

    return names
}

func HashNames() []string {
    return defaultHash.Names()
}
