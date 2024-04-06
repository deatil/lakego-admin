package pkcs7

import (
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/hash/sm3"
)

var (
    // Digest Algorithms
    OidDigestAlgorithmMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
    OidDigestAlgorithmSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
    OidDigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
    OidDigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
    OidDigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
    OidDigestAlgorithmSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}

    OidDigestAlgorithmSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
)

var SignHashWithMD5 = SignHashWithFunc{
    hashFunc:   md5.New,
    identifier: OidDigestAlgorithmMD5,
}
var SignHashWithSHA1 = SignHashWithFunc{
    hashFunc:   sha1.New,
    identifier: OidDigestAlgorithmSHA1,
}
var SignHashWithSHA256 = SignHashWithFunc{
    hashFunc:   sha256.New,
    identifier: OidDigestAlgorithmSHA256,
}
var SignHashWithSHA384 = SignHashWithFunc{
    hashFunc:   sha512.New384,
    identifier: OidDigestAlgorithmSHA384,
}
var SignHashWithSHA512 = SignHashWithFunc{
    hashFunc:   sha512.New,
    identifier: OidDigestAlgorithmSHA512,
}
var SignHashWithSHA224 = SignHashWithFunc{
    hashFunc:   sha256.New224,
    identifier: OidDigestAlgorithmSHA224,
}

var SignHashWithSM3 = SignHashWithFunc{
    hashFunc:   sm3.New,
    identifier: OidDigestAlgorithmSM3,
}

func init() {
    // MD5
    AddSignHash(OidDigestAlgorithmMD5, func() SignHash {
        return SignHashWithMD5
    })

    // SHA
    AddSignHash(OidDigestAlgorithmSHA1, func() SignHash {
        return SignHashWithSHA1
    })
    AddSignHash(OidDigestAlgorithmSHA256, func() SignHash {
        return SignHashWithSHA256
    })
    AddSignHash(OidDigestAlgorithmSHA384, func() SignHash {
        return SignHashWithSHA384
    })
    AddSignHash(OidDigestAlgorithmSHA512, func() SignHash {
        return SignHashWithSHA512
    })
    AddSignHash(OidDigestAlgorithmSHA224, func() SignHash {
        return SignHashWithSHA224
    })

    // SM3
    AddSignHash(OidDigestAlgorithmSM3, func() SignHash {
        return SignHashWithSM3
    })
}
