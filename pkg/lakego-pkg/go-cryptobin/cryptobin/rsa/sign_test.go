package rsa

import (
    "bytes"
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

// 大数据加密
func rsaBigDataEncrypt(plainText, publicKey []byte) (cipherText []byte, err error) {
    rsa := FromPublicKey(publicKey)

    pub := rsa.GetPublicKey()
    pubSize, plainTextSize := pub.Size(), len(plainText)

    offSet, once := 0, pubSize-11

    buffer := bytes.Buffer{}
    for offSet < plainTextSize {
        endIndex := offSet + once
        if endIndex > plainTextSize {
            endIndex = plainTextSize
        }

        rsa2 := rsa.FromBytes(plainText[offSet:endIndex]).Encrypt()

        err := rsa2.Error()
        if err != nil {
            return nil, err
        }

        bytesOnce := rsa2.ToBytes()

        buffer.Write(bytesOnce)
        offSet = endIndex
    }

    cipherText = buffer.Bytes()
    return cipherText, nil
}

// 大数据解密
func rsaBigDataDecrypt(cipherText, privateKey []byte) (plainText []byte, err error) {
    rsa := FromPrivateKey(privateKey)
    pri := rsa.GetPrivateKey()

    priSize, cipherTextSize := pri.Size(), len(cipherText)
    var offSet = 0
    var buffer = bytes.Buffer{}

    for offSet < cipherTextSize {
        endIndex := offSet + priSize
        if endIndex > cipherTextSize {
            endIndex = cipherTextSize
        }

        rsa2 := rsa.FromBytes(cipherText[offSet:endIndex]).Decrypt()

        err := rsa2.Error()
        if err != nil {
            return nil, err
        }

        bytesOnce := rsa2.ToBytes()

        buffer.Write(bytesOnce)
        offSet = endIndex
    }

    plainText = buffer.Bytes()
    return plainText, nil
}

var (
    testPrikey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsNezdXME/HjdoLu5tjfvydIEgWCXhK9KYxBWUEKx/4VFkAnf
QQ6I2DmZbkCWD12NRhaGfH7Cd1Nwg5TPWPJXO6P/GtgqOeOryaOgyUJ+mONXQxyS
UwXjRWRIOIv8Tr5Yz7akqqWjSZbkaETyFvwEM0DhJLzv+36wgyWPzKuY/0HFfufx
k2MPZonK8N6mtOiTFgyyYTnCojdSQwevjJlL9jt+ymAqjqdSy8QLqN78+bhFWDHe
PERe8aOmR0Ovq5keBM4K/tcFvHH/QUKkyJ/gXHXC1M1TqzlssmZ5s2OFMIjHROez
nfbKbRgKMxvTafNkawskxq36sp6dvalgueJh4QIDAQABAoIBAQCeVlOJSpXhVHrj
6pGKVKUvaAq+qHShya1p63vM2xqytWomYKBziIcASvpUnCF/2nyej5aUq46E9sGc
HsZUVo/Ch8DnETsln/L1VLum2BGv5IYCQffFvFTUkciUUMp02rt8J4VigXIldqRF
s82qxLUiCupLUZvx62ox0pThZZdUm9lJNswWx79v4bXPN9c83h8tsXjRMcOc7SNk
GTb10kQK9t8OJ7mANO9uTUtmeFySDm0v1808N4a7MHeQhBhmJJY45waW3IPW2XLi
6e9BFF5C4eRLCe5CGliIhRNUsqBAnuTMj0YhDZe3LlxD2SAbN8NeX0NvIU/lGuMd
iADa7vnRAoGBAOsBJLqPC94oUM7KKhjJHQpfTYq750WhNJqi7r5PTh6/ULdVN+Wt
RJRvzCa1pDm7BlHIAyE8Ik10y9yCv7lLqc7OaTEWgmjmSFmgXCm1zVc4M+SsaOyM
FU7xcZq6f53kV6/+SUIj9sEyRqshkQUa+KqtJzbw4yNq5z7iiaKbn6QtAoGBAMCk
UeV1L/mUq1MPrQ/FG/gjdV2wMQtmbFDF8znz5O/X2Fi3+Ayna7TJUjMWYqe7VWrF
+ZZBUCo/UalrC9tru03hNNd5QDj8RRA/V4tUNmWY811AuNwB6Z9abzBvFLNjj+0G
elfW/QSfq6Y7d1tqMLPyjej/4FGI6Mt5BfvEoAEFAoGAUgIGJSxCAfajrGYUJq4X
+kSjtKQ54qyMxOHS2oqmQkiVDEUqynWalwokfeWpN5QycluP7AsmFU2Kzpq5+RmU
WlzhjIXEYILsAIrbXprY23T7dvNLcjC4RuIuuMYYPqsuhnYAbppKQ8UdsB54kwWE
fVsLcjrBqNxnciRvz1TrcskCgYB7dBKjuODg0fylQ0OF+qx87cRWIQadJqs9bE3+
EqXhanLUEDmfal9kwSuzX6IjmbMYtPzI5NxJ5sAfkWFM4ZJsS2nAuIyGuGxOCDnD
KVme7FDxrvuIypT8MUlWQamDeMeQf3lB9524K9cltbA83iWN/GAjNG998P42/zzt
ZsmfPQKBgBQ1IRvDp+Knu7gR8W0Q5WdP8YWIUsvALKju97xadhTTZKVMJydoWse6
cmAsSGNAgn8sNmchc6PCn1ITh0YLXceZsQOMNqoWXr4AIRIHB1bBtigXczgliURp
ckSPTzjIBa9x5dU7yFnztQ18APuSd70nnMdZv/ilJsSZbYyiFSyY
-----END RSA PRIVATE KEY-----
    `
    testPubkey = `
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAsNezdXME/HjdoLu5tjfvydIEgWCXhK9KYxBWUEKx/4VFkAnfQQ6I
2DmZbkCWD12NRhaGfH7Cd1Nwg5TPWPJXO6P/GtgqOeOryaOgyUJ+mONXQxySUwXj
RWRIOIv8Tr5Yz7akqqWjSZbkaETyFvwEM0DhJLzv+36wgyWPzKuY/0HFfufxk2MP
ZonK8N6mtOiTFgyyYTnCojdSQwevjJlL9jt+ymAqjqdSy8QLqN78+bhFWDHePERe
8aOmR0Ovq5keBM4K/tcFvHH/QUKkyJ/gXHXC1M1TqzlssmZ5s2OFMIjHROeznfbK
bRgKMxvTafNkawskxq36sp6dvalgueJh4QIDAQAB
-----END RSA PUBLIC KEY-----
    `
)

func Test_BigDataEncrypt(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := []byte("test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass3333333333333333333333333333333333333333333333333333test-pa2222222222222222222222222222222222222222222sstest-passt111111111111111111111111111111111est-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass")

    encoded, err := rsaBigDataEncrypt(data, []byte(testPubkey))
    assertError(err, "BigDataEncrypt-Encrypt")

    decoded, err2 := rsaBigDataDecrypt(encoded, []byte(testPrikey))
    assertError(err2, "BigDataEncrypt-Decrypt")

    assert(data, decoded, "BigDataEncrypt")
}
