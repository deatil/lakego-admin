package hash

import (
    "crypto"
    "crypto/hmac"
)

// NewHmac
func (this Hash) NewHmac(hash crypto.Hash, secret []byte) Hash {
    this.hash = hmac.New(hash.New, secret)

    return this
}

// ============================================

// HmacMd4 哈希值
func (this Hash) HmacMd4(secret []byte) Hash {
    this.data = hmacHash(crypto.MD4, this.data, secret)

    return this
}

// NewHmacMd4
func (this Hash) NewHmacMd4(secret []byte) Hash {
    return this.NewHmac(crypto.MD4, secret)
}

// ============================================

// HmacMd5 哈希值
func (this Hash) HmacMd5(secret []byte) Hash {
    this.data = hmacHash(crypto.MD5, this.data, secret)

    return this
}

// NewHmacMd5
func (this Hash) NewHmacMd5(secret []byte) Hash {
    return this.NewHmac(crypto.MD5, secret)
}

// ============================================

// HmacSHA1 哈希值
func (this Hash) HmacSHA1(secret []byte) Hash {
    this.data = hmacHash(crypto.SHA1, this.data, secret)

    return this
}

// NewHmacSHA1
func (this Hash) NewHmacSHA1(secret []byte) Hash {
    return this.NewHmac(crypto.SHA1, secret)
}

// ============================================

// HmacSha224 哈希值
func (this Hash) HmacSha224(secret []byte) Hash {
    this.data = hmacHash(crypto.SHA224, this.data, secret)

    return this
}

// NewHmacSha224
func (this Hash) NewHmacSha224(secret []byte) Hash {
    return this.NewHmac(crypto.SHA224, secret)
}

// ============================================

// HmacSha256 哈希值
func (this Hash) HmacSha256(secret []byte) Hash {
    this.data = hmacHash(crypto.SHA256, this.data, secret)

    return this
}

// NewHmacSha256
func (this Hash) NewHmacSha256(secret []byte) Hash {
    return this.NewHmac(crypto.SHA256, secret)
}

// ============================================

// HmacSha384 哈希值
func (this Hash) HmacSha384(secret []byte) Hash {
    this.data = hmacHash(crypto.SHA384, this.data, secret)

    return this
}

// NewHmacSha384
func (this Hash) NewHmacSha384(secret []byte) Hash {
    return this.NewHmac(crypto.SHA384, secret)
}

// ============================================

// HmacSha512 哈希值
func (this Hash) HmacSha512(secret []byte) Hash {
    this.data = hmacHash(crypto.SHA512, this.data, secret)

    return this
}

// NewHmacSha512
func (this Hash) NewHmacSha512(secret []byte) Hash {
    return this.NewHmac(crypto.SHA512, secret)
}

// ============================================

// HmacRipemd160 哈希值
func (this Hash) HmacRipemd160(secret []byte) Hash {
    this.data = hmacHash(crypto.RIPEMD160, this.data, secret)

    return this
}

// NewHmacRipemd160
func (this Hash) NewHmacRipemd160(secret []byte) Hash {
    return this.NewHmac(crypto.RIPEMD160, secret)
}

// ============================================

// 签名
func hmacHash(hash crypto.Hash, message, secret []byte) []byte {
    h := hmac.New(hash.New, secret)
    h.Write(message)

    return h.Sum(nil)
}
