package rsa

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_LowerSafeEncrypt(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    testPub := []byte(testPublicKeyCheck)
    pub, err := ParseXMLPublicKey(testPub)

    assertError(err, "Test_LowerSafeEncrypt-pub-Error")

    testPri := []byte(testPrivateKeyCheck)
    pri, err := ParseXMLPrivateKey(testPri)

    assertError(err, "Test_LowerSafeEncrypt-pri-Error")

    msg := []byte("test-test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datadata")

    ct, err := LowerSafeEncrypt(pub, msg)
    assertError(err, "Test_LowerSafeEncrypt-en-Error")

    res, err := LowerSafeDecrypt(pri, ct)
    assertError(err, "Test_LowerSafeEncrypt-de-Error")

    assertEqual(string(res), string(msg), "Test_LowerSafeEncrypt")
}
