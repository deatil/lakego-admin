package hash

import (
    "crypto/md5"
    "crypto/sha1"
)

func sha1Hash(slice []byte) []byte {
    h := sha1.New()
    h.Write(slice)

    return h.Sum(nil)
}

// MD5SHA1 哈希值
func md5Sha1(slice []byte) []byte {
    md5sha1 := make([]byte, md5.Size + sha1.Size)

    h := md5.New()
    h.Write(slice)

    copy(md5sha1, h.Sum(nil))
    copy(md5sha1[md5.Size:], sha1Hash(slice))

    return md5sha1[:]
}

// MD5SHA1 哈希值
func (this Hash) MD5SHA1() Hash {
    this.data = md5Sha1(this.data)

    return this
}

