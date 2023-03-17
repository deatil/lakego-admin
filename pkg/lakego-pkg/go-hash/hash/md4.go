package hash

import (
    "golang.org/x/crypto/md4"
)

// MD4 哈希值
func (this Hash) MD4() Hash {
    h := md4.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewMD4
func (this Hash) NewMD4() Hash {
    this.hash = md4.New()

    return this
}
