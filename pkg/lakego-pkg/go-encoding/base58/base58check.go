package base58

import (
    "errors"
    "crypto/sha256"
)

var ErrChecksum = errors.New("checksum error")
var ErrInvalidFormat = errors.New("invalid format: version and/or checksum bytes missing")

func checksum(input []byte) (cksum [4]byte) {
    h := sha256.Sum256(input)
    h2 := sha256.Sum256(h[:])
    copy(cksum[:], h2[:4])
    return
}

// Check Encode
func CheckEncode(input []byte, version byte) string {
    b := make([]byte, 0, 1+len(input)+4)
    b = append(b, version)
    b = append(b, input...)

    cksum := checksum(b)

    b = append(b, cksum[:]...)

    return StdEncoding.EncodeToString(b)
}

// Check Decode
func CheckDecode(input string) (result []byte, version byte, err error) {
    decoded, _ := StdEncoding.DecodeString(input)
    if len(decoded) < 5 {
        return nil, 0, ErrInvalidFormat
    }

    version = decoded[0]
    var cksum [4]byte
    copy(cksum[:], decoded[len(decoded)-4:])
    if checksum(decoded[:len(decoded)-4]) != cksum {
        return nil, 0, ErrChecksum
    }

    payload := decoded[1 : len(decoded)-4]
    result = append(result, payload...)

    return
}
