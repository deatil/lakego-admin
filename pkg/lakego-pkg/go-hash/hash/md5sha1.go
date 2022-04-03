package hash

import (
    "crypto/md5"
    "crypto/sha1"
    "encoding/hex"
)

func sha1Hash(slices ...string) []byte {
    hsha1 := sha1.New()
    for _, slice := range slices {
        hsha1.Write([]byte(slice))
    }

    return hsha1.Sum(nil)
}

// MD5SHA1 哈希值
func MD5SHA1(slices ...string) string {
    md5sha1 := make([]byte, md5.Size + sha1.Size)

    hmd5 := md5.New()
    for _, slice := range slices {
        hmd5.Write([]byte(slice))
    }

    copy(md5sha1, hmd5.Sum(nil))
    copy(md5sha1[md5.Size:], sha1Hash(slices...))

    return hex.EncodeToString(md5sha1[:])
}

// MD5SHA1 哈希值
func (this Hash) MD5SHA1() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        var newData []string
        for _, v := range data {
            newData = append(newData, string(v))
        }

        return MD5SHA1(newData...), nil
    })
}

