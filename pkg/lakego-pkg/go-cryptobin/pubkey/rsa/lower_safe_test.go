package rsa

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_LowerSafeEncrypt(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    testPub := []byte(testPublicKeyCheck)
    pub, err := ParseXMLPublicKey(testPub)

    assertNoError(err, "Test_LowerSafeEncrypt-pub-Error")

    testPri := []byte(testPrivateKeyCheck)
    pri, err := ParseXMLPrivateKey(testPri)

    assertNoError(err, "Test_LowerSafeEncrypt-pri-Error")

    msg := []byte("test-test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datadata")

    ct, err := LowerSafeEncrypt(pub, msg)
    assertNoError(err, "Test_LowerSafeEncrypt-en-Error")

    res, err := LowerSafeDecrypt(pri, ct)
    assertNoError(err, "Test_LowerSafeEncrypt-de-Error")

    assertEqual(string(res), string(msg), "Test_LowerSafeEncrypt")
}
