package hash

import (
    "crypto/md5"
)

// MD5
func (this Hash) MD5() Hash {
    h := md5.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewMD5
func (this Hash) NewMD5() Hash {
    this.hash = md5.New()

    return this
}
