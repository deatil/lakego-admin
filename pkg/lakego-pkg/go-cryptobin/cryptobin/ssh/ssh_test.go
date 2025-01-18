package ssh

import (
    "fmt"
    "errors"
    "testing"
    "crypto/dsa"
    "crypto/rsa"
    "crypto/rand"
    "crypto/elliptic"

    cryptobin_ssh "github.com/deatil/go-cryptobin/ssh"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_GenKey(t *testing.T) {
    cases := []string{
        "RSA",
        "DSA",
        "ECDSA",
        "EdDSA",
        "SM2",
    }

    for _, c := range cases {
        t.Run(c, func(t *testing.T) {
            test_GenKey(t, c)
        })
    }
}

func test_GenKey(t *testing.T, keyType string) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().SetPublicKeyType(keyType).GenerateKey()
    assertError(obj.Error(), "Test_GenKey")

    {
        prikey := obj.CreateOpenSSHPrivateKey().ToKeyBytes()
        assertNotEmpty(prikey, "Test_GenKey-PrivateKey")

        pubkey := obj.CreateOpenSSHPublicKey().ToKeyBytes()
        assertNotEmpty(pubkey, "Test_GenKey-PublicKey")

        // t.Errorf("%s, %s \n", string(prikey), string(pubkey))

        newSSH := New().FromOpenSSHPrivateKey(prikey)
        assertError(newSSH.Error(), "Test_GenKey-newSSH")

        assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH")

        newSSH2 := New().FromOpenSSHPublicKey(pubkey)
        assertError(newSSH2.Error(), "Test_GenKey-newSSH2")

        assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey-newSSH2")
    }

    {
        password := []byte("test-password")

        prikey3 := obj.CreateOpenSSHPrivateKeyWithPassword(password).ToKeyBytes()
        assertNotEmpty(prikey3, "Test_GenKey-PrivateKey 3")

        newSSH3 := New().FromOpenSSHPrivateKeyWithPassword(prikey3, password)
        assertError(newSSH3.Error(), "Test_GenKey-newSSH3")

        assertEqual(newSSH3.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH3")
    }
}

func Test_GenKey2(t *testing.T) {
    cases := []string{
        "RSA",
        "DSA",
        "ECDSA",
        "EdDSA",
        "SM2",
    }

    for _, c := range cases {
        t.Run(c, func(t *testing.T) {
            test_GenKey2(t, c)
        })
    }
}

func test_GenKey2(t *testing.T, keyType string) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().SetPublicKeyType(keyType).GenerateKey()
    assertError(obj.Error(), "Test_GenKey")

    {
        assertEqual(obj.GetPrivateKeyType().String(), keyType, "Test_GenKey-GetPrivateKeyType")
        assertEqual(obj.GetPublicKeyType().String(), keyType, "Test_GenKey-GetPublicKeyType")
    }

    {
        prikey := obj.CreatePrivateKey().ToKeyBytes()
        assertNotEmpty(prikey, "Test_GenKey-PrivateKey")

        pubkey := obj.CreatePublicKey().ToKeyBytes()
        assertNotEmpty(pubkey, "Test_GenKey-PublicKey")

        // t.Errorf("%s, %s \n", string(prikey), string(pubkey))

        newSSH := New().FromPrivateKey(prikey)
        assertError(newSSH.Error(), "Test_GenKey-newSSH")

        assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH")

        newSSH2 := New().FromPublicKey(pubkey)
        assertError(newSSH2.Error(), "Test_GenKey-newSSH2")

        assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey-newSSH2")
    }

    {
        password := []byte("test-password")

        prikey3 := obj.CreatePrivateKeyWithPassword(password).ToKeyBytes()
        assertNotEmpty(prikey3, "Test_GenKey-PrivateKey 3")

        newSSH3 := New().FromPrivateKeyWithPassword(prikey3, password)
        assertError(newSSH3.Error(), "Test_GenKey-newSSH3")

        assertEqual(newSSH3.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH3")
    }
}

func Test_GenKey3(t *testing.T) {
    cases := []PublicKeyType{
        KeyTypeRSA,
        KeyTypeDSA,
        KeyTypeECDSA,
        KeyTypeEdDSA,
        KeyTypeSM2,
    }

    for _, c := range cases {
        t.Run(c.String(), func(t *testing.T) {
            test_GenKey3(t, c)
        })
    }
}

func test_GenKey3(t *testing.T, keyType PublicKeyType) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    newOpts := func(ktype PublicKeyType) Options {
        opt := Options{
            PublicKeyType:  ktype,
            ParameterSizes: dsa.L1024N160,
            Curve:          elliptic.P256(),
            Bits:           2048,
        }

        return opt
    }

    obj := GenerateKey(newOpts(keyType))
    assertError(obj.Error(), "Test_GenKey3")

    {
        prikey := obj.CreatePrivateKey().ToKeyBytes()
        assertNotEmpty(prikey, "Test_GenKey3-PrivateKey")

        pubkey := obj.CreatePublicKey().ToKeyBytes()
        assertNotEmpty(pubkey, "Test_GenKey3-PublicKey")

        // t.Errorf("%s, %s \n", string(prikey), string(pubkey))

        newSSH := New().FromPrivateKey(prikey)
        assertError(newSSH.Error(), "Test_GenKey3-newSSH")

        assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey3-newSSH")

        newSSH2 := New().FromPublicKey(pubkey)
        assertError(newSSH2.Error(), "Test_GenKey3-newSSH2")

        assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey3-newSSH2")
    }

    {
        password := []byte("test-password")

        prikey3 := obj.CreatePrivateKeyWithPassword(password).ToKeyBytes()
        assertNotEmpty(prikey3, "Test_GenKey3-PrivateKey 3")

        newSSH3 := New().FromPrivateKeyWithPassword(prikey3, password)
        assertError(newSSH3.Error(), "Test_GenKey3-newSSH3")

        assertEqual(newSSH3.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey3-newSSH3")
    }
}

func Test_GenKey5(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey()
    assertError(obj.Error(), "Test_GenKey5")

    {
        prikey := obj.CreatePrivateKey().ToKeyBytes()
        assertNotEmpty(prikey, "Test_GenKey5-PrivateKey")

        pubkey := obj.CreatePublicKey().ToKeyBytes()
        assertNotEmpty(pubkey, "Test_GenKey5-PublicKey")

        newSSH := New().FromPrivateKey(prikey)
        assertError(newSSH.Error(), "Test_GenKey5-newSSH")

        assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey3-newSSH")

        newSSH2 := New().FromPublicKey(pubkey)
        assertError(newSSH2.Error(), "Test_GenKey5-newSSH2")

        assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey5-newSSH2")
    }

    {
        password := []byte("test-password")

        prikey3 := obj.CreatePrivateKeyWithPassword(password).ToKeyBytes()
        assertNotEmpty(prikey3, "Test_GenKey5-PrivateKey 3")

        newSSH3 := New().FromPrivateKeyWithPassword(prikey3, password)
        assertError(newSSH3.Error(), "Test_GenKey5-newSSH3")

        assertEqual(newSSH3.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey5-newSSH3")
    }
}

func Test_GenKey_ECDSA(t *testing.T) {
    cases := []string{
        "P256",
        "P384",
        "P521",
    }

    for _, c := range cases {
        t.Run(c, func(t *testing.T) {
            test_GenKey_ECDSA(t, c)
        })
    }
}

func test_GenKey_ECDSA(t *testing.T, curve string) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().
        SetPublicKeyType("ECDSA").
        SetCurve(curve).
        GenerateKey()
    assertError(obj.Error(), "Test_GenKey_ECDSA")

    prikey := obj.CreateOpenSSHPrivateKey().ToKeyBytes()
    assertNotEmpty(prikey, "Test_GenKey_ECDSA-PrivateKey")

    pubkey := obj.CreateOpenSSHPublicKey().ToKeyBytes()
    assertNotEmpty(pubkey, "Test_GenKey_ECDSA-PublicKey")

    newSSH := New().FromOpenSSHPrivateKey(prikey)
    assertError(newSSH.Error(), "Test_GenKey_ECDSA-newSSH")

    assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey_ECDSA-newSSH")

    newSSH2 := New().FromOpenSSHPublicKey(pubkey)
    assertError(newSSH2.Error(), "Test_GenKey_ECDSA-newSSH2")

    assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey_ECDSA-newSSH2")
}

func Test_GenKey_ECDSA_With_Comment(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    comment := "test-comment"

    obj := New().
        SetPublicKeyType("ECDSA").
        GenerateKey()
    assertError(obj.Error(), "Test_GenKey_ECDSA_With_Comment")

    prikey := obj.WithComment(comment).
        CreateOpenSSHPrivateKey().
        ToKeyBytes()
    assertNotEmpty(prikey, "Test_GenKey_ECDSA_With_Comment-PrivateKey")

    pubkey := obj.WithComment(comment).
        CreateOpenSSHPublicKey().
        ToKeyBytes()
    assertNotEmpty(pubkey, "Test_GenKey_ECDSA_With_Comment-PublicKey")

    newSSH := New().FromOpenSSHPrivateKey(prikey)
    assertError(newSSH.Error(), "Test_GenKey_ECDSA_With_Comment-newSSH")

    assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey_ECDSA_With_Comment-newSSH")
    assertEqual(newSSH.GetComment(), comment, "Test_GenKey_ECDSA_With_Comment-newSSH-comment")

    newSSH2 := New().FromOpenSSHPublicKey(pubkey)
    assertError(newSSH2.Error(), "Test_GenKey_ECDSA_With_Comment-newSSH2")

    assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey_ECDSA_With_Comment-newSSH2")
    assertEqual(newSSH2.GetComment(), comment, "Test_GenKey_ECDSA_With_Comment-newSSH2-comment")
}

func Test_OnError(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    err := errors.New("test-error")

    testssh := New()
    testssh.Errors = append(testssh.Errors, err)

    testssh = testssh.OnError(func(errs []error) {
        assertEqual(errs, []error{err}, "Test_OnError")
    })

    err2 := testssh.Error().Error()
    assertEqual(err2, err.Error(), "Test_OnError Error")
}

func Test_Get(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    publicKey := &privateKey.PublicKey

    testerr := errors.New("test-error")
    opts := Options{
        PublicKeyType:  KeyTypeRSA,
        CipherName:     "test-CipherName",
        Comment:        "test-Comment",
        ParameterSizes: dsa.L1024N160,
        Curve:          elliptic.P256(),
        Bits:           2048,
    }

    newSSH2 := SSH{
        privateKey: privateKey,
        publicKey:  publicKey,
        options:    opts,
        keyData:    []byte("test-keyData"),
        data:       []byte("test-data"),
        parsedData: []byte("test-parsedData"),
        verify: false,
        Errors: []error{testerr},
    }

    assertEqual(newSSH2.GetPrivateKey(), privateKey, "Test_Get-GetPrivateKey")
    assertEqual(newSSH2.GetPrivateKeyType().String(), "RSA", "Test_Get-GetPrivateKeyType")

    openSSHSigner, err := newSSH2.GetOpenSSHSigner()
    assertError(err, "Test_Get-GetOpenSSHSigner")
    assertNotEmpty(openSSHSigner, "Test_Get-GetOpenSSHSigner")

    assertEqual(newSSH2.GetPublicKey(), publicKey, "Test_Get-GetPublicKey")
    assertEqual(newSSH2.GetPublicKeyType().String(), "RSA", "Test_Get-GetPublicKeyType")

    openSSHPublicKey, err := newSSH2.GetOpenSSHPublicKey()
    assertError(err, "Test_Get-GetOpenSSHPublicKey")
    assertNotEmpty(openSSHPublicKey, "Test_Get-GetOpenSSHPublicKey")

    assertEqual(newSSH2.GetOptions(), opts, "Test_Get-GetOptions")
    assertEqual(newSSH2.GetCipherName(), "test-CipherName", "Test_Get-GetCipherName")
    assertEqual(newSSH2.GetComment(), "test-Comment", "Test_Get-GetComment")
    assertEqual(newSSH2.GetParameterSizes(), dsa.L1024N160, "Test_Get-GetParameterSizes")
    assertEqual(newSSH2.GetCurve(), elliptic.P256(), "Test_Get-GetCurve")
    assertEqual(newSSH2.GetBits(), 2048, "Test_Get-GetBits")

    assertEqual(newSSH2.GetKeyData(), []byte("test-keyData"), "Test_Get-GetKeyData")
    assertEqual(newSSH2.GetData(), []byte("test-data"), "Test_Get-GetData")
    assertEqual(newSSH2.GetParsedData(), []byte("test-parsedData"), "Test_Get-GetParsedData")
    assertEqual(newSSH2.GetVerify(), false, "Test_Get-GetVerify")
    assertEqual(newSSH2.GetErrors(), []error{testerr}, "Test_Get-GetErrors")

    assertEqual(newSSH2.ToKeyBytes(), []byte("test-keyData"), "Test_Get-ToKeyBytes")
    assertEqual(newSSH2.ToKeyString(), "test-keyData", "Test_Get-ToKeyString")

    assertEqual(newSSH2.ToBytes(), []byte("test-parsedData"), "Test_Get-ToBytes")
    assertEqual(newSSH2.ToString(), "test-parsedData", "Test_Get-ToString")
    assertEqual(newSSH2.ToBase64String(), "dGVzdC1wYXJzZWREYXRh", "Test_Get-ToBase64String")
    assertEqual(newSSH2.ToHexString(), "746573742d70617273656444617461", "Test_Get-ToHexString")

    assertEqual(newSSH2.ToVerify(), false, "Test_Get-ToVerify")
    assertEqual(newSSH2.ToVerifyInt(), 0, "Test_Get-ToVerifyInt")
}

func Test_With(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    publicKey := &privateKey.PublicKey

    testerr := errors.New("test-error")
    opts := Options{
        PublicKeyType:  KeyTypeRSA,
        Comment:        "test-Comment",
        ParameterSizes: dsa.L1024N160,
        Curve:          elliptic.P256(),
        Bits:           2048,
    }

    var tmp SSH

    newSSH := SSH{}

    tmp = newSSH.WithPrivateKey(privateKey)
    assertEqual(tmp.privateKey, privateKey, "Test_Get-WithPrivateKey")

    tmp = newSSH.WithPublicKey(publicKey)
    assertEqual(tmp.publicKey, publicKey, "Test_Get-WithPublicKey")

    tmp = newSSH.WithOptions(opts)
    assertEqual(tmp.options, opts, "Test_Get-WithOptions")

    tmp = newSSH.WithPublicKeyType(KeyTypeRSA)
    assertEqual(tmp.options.PublicKeyType, KeyTypeRSA, "Test_Get-WithPublicKeyType")

    tmp = newSSH.SetPublicKeyType("ECDSA")
    assertEqual(tmp.options.PublicKeyType, KeyTypeECDSA, "Test_Get-SetPublicKeyType")

    tmp = newSSH.SetGenerateType("EdDSA")
    assertEqual(tmp.options.PublicKeyType, KeyTypeEdDSA, "Test_Get-SetGenerateType")

    tmp = newSSH.WithCipherName("test-CipherName")
    assertEqual(tmp.options.CipherName, "test-CipherName", "Test_Get-WithCipherName")

    tmp = newSSH.SetCipher(cryptobin_ssh.AES256CBC)
    assertEqual(tmp.options.CipherName, "aes256-cbc", "Test_Get-SetCipher")

    tmp = newSSH.WithComment("test-Comment")
    assertEqual(tmp.options.Comment, "test-Comment", "Test_Get-WithComment")

    tmp = newSSH.WithParameterSizes(dsa.L1024N160)
    assertEqual(tmp.options.ParameterSizes, dsa.L1024N160, "Test_Get-WithParameterSizes")

    tmp = newSSH.SetParameterSizes("L2048N224")
    assertEqual(tmp.options.ParameterSizes, dsa.L2048N224, "Test_Get-SetParameterSizes")

    tmp = newSSH.WithCurve(elliptic.P384())
    assertEqual(tmp.options.Curve, elliptic.P384(), "Test_Get-WithCurve")

    tmp = newSSH.SetCurve("P521")
    assertEqual(tmp.options.Curve, elliptic.P521(), "Test_Get-SetCurve")

    tmp = newSSH.WithBits(2048)
    assertEqual(tmp.options.Bits, 2048, "Test_Get-WithBits")

    tmp = newSSH.WithKeyData([]byte("test-keyData"))
    assertEqual(tmp.keyData, []byte("test-keyData"), "Test_Get-WithKeyData")

    tmp = newSSH.WithData([]byte("test-data"))
    assertEqual(tmp.data, []byte("test-data"), "Test_Get-WithData")

    tmp = newSSH.WithParsedData([]byte("test-parsedData"))
    assertEqual(tmp.parsedData, []byte("test-parsedData"), "Test_Get-WithParsedData")

    tmp = newSSH.WithVerify(true)
    assertEqual(tmp.verify, true, "Test_Get-WithVerify")

    tmp = newSSH.WithErrors([]error{testerr})
    assertEqual(tmp.Errors, []error{testerr}, "Test_Get-WithErrors")
}

func Test_Error(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    testerr := errors.New("test-error")

    var tmp SSH

    newSSH := SSH{}

    tmp = newSSH.AppendError(testerr)
    assertEqual(tmp.Errors, []error{testerr}, "Test_Error-AppendError")

    err2 := tmp.Error().Error()
    assertEqual(err2, testerr.Error(), "Test_Error-Error")
}

var opensshprikey = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdz
c2gtcnNhAAAAAwEAAQAAAQEAw9pq06KE3T2j+7Gxq7DM2WQ7gna5PNL2FLV1TcEJ
KSrxpg/uKhScLkwHV/pvL+etVm3WrO4T2lZZgGZySPU0MpQ9gTgjhPh3Iy0bgZ38
0WelGCSAQ044XadTvRcsVMes/kJ2HG36RO9rbzinX+esFlgNN5BtjLAQDYV/KmPU
dqYQIT2wU7lIAh4g+G0n+w3wKpGuAQnhqDqca6bGjYQEJnzcLVMvOTd7K59EIOSQ
52C0fSiWLt5R542QxE+H0icNTwQS1gjfVStCMOsXdja86naIBdu6r+rXrKVHMjOf
/HFQ2rw9DQ1q12w5XWZMLUE07NCFek0kHmTLISzec3GjOQAAA8EMgLTuDIC07gAA
AAdzc2gtcnNhAAABAQDD2mrTooTdPaP7sbGrsMzZZDuCdrk80vYUtXVNwQkpKvGm
D+4qFJwuTAdX+m8v561Wbdas7hPaVlmAZnJI9TQylD2BOCOE+HcjLRuBnfzRZ6UY
JIBDTjhdp1O9FyxUx6z+QnYcbfpE72tvOKdf56wWWA03kG2MsBANhX8qY9R2phAh
PbBTuUgCHiD4bSf7DfAqka4BCeGoOpxrpsaNhAQmfNwtUy85N3srn0Qg5JDnYLR9
KJYu3lHnjZDET4fSJw1PBBLWCN9VK0Iw6xd2NrzqdogF27qv6tespUcyM5/8cVDa
vD0NDWrXbDldZkwtQTTs0IV6TSQeZMshLN5zcaM5AAAAAwEAAQAAAQAtVaeYqWvb
0mLc5frcZSZlw7/KqTSjkamIjaBDiUVXlCsvZ0yXzQGB7fNdOAj4q8YB1Zb1nH5X
8djx0cTugmO8uXerK5V9OA5LxCszy6Az0Kv0dK6D5d1CQHMvt+d5EGdIy5WPax2d
S1Yw/oovtu6slWEp1XKmODLfDmGrLESH2eyICG0L1NPiexwA2qYi2Aj7HPXs7PgV
DClc8+CL6C+Yl0+y/5Uq/qi5Gg59t0+uSw1GFbkpQxQ+INzO8nS/NwXVIXE0VlQ3
NimaI7dmsUaHGzi4LDjm2pEBBzdEQFb5TrN8YxjN8+TeayHdvVNgFUth+kZpsV7Q
RbKq2BpycczpAAAAgGW1gZb6ugVlqwGcRH0LK4+tBLY48ftGrOO6Wd7teKwHNq+V
xrLZvJ+vWY3Jww+TlkgaGHIGap/dUdXHMooskK69cmZEcobQfSqiBGcsmP9/0z6C
2lVsFNK6BfAAx2uOc0570rg+q36f4FgAnaueHkYXseJNzcVWJCYjXP9NQErKAAAA
gQDLREVn1etFyTyLHz5MZmLzfpGQu0PXSoIP8LiyNDKlwaTjUPkr6/CH0b9yEb+p
KtoqKfYKH7cH3VfjboEGN2WBpNfbeyXN1qr0vHClX+VOY4EBNb5Skprn99m5ytfn
g4SuwYvcVpl6xMcSOm75wGG8BA7X4N1ig7uZqLjw4SfVLwAAAIEA9qnJlmrwrPIO
INW6vPowAIAGLAYJdSdG1dXvXtcyMPxnPU1cipljX6C0QU5C9CExH9Jr1cEeFWbn
j9cVsSGYLuGR74DUrmAvwmWBItVWGj6z6v7gq7uldp14N3MK7yeXIQRSNbJKLJUx
e+do10dMBiKLMpylg0W8Nn2AoVpTRBcAAAAMdXNlckB3ZWIuY29t
-----END OPENSSH PRIVATE KEY-----
`

var opensshpubkey = `
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDD2mrTooTdPaP7sbGrsMzZZDuCdrk80vYUtXVNwQkpKvGmD+4qFJwuTAdX+m8v561Wbdas7hPaVlmAZnJI9TQylD2BOCOE+HcjLRuBnfzRZ6UYJIBDTjhdp1O9FyxUx6z+QnYcbfpE72tvOKdf56wWWA03kG2MsBANhX8qY9R2phAhPbBTuUgCHiD4bSf7DfAqka4BCeGoOpxrpsaNhAQmfNwtUy85N3srn0Qg5JDnYLR9KJYu3lHnjZDET4fSJw1PBBLWCN9VK0Iw6xd2NrzqdogF27qv6tespUcyM5/8cVDavD0NDWrXbDldZkwtQTTs0IV6TSQeZMshLN5zcaM5 user@web.com
`

var opensshprikeyEn = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABAj
j6QR7gtMhCcL0hNVI7G1AAAAEAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAAB
AQDsUGub8db33AsanqRw4wmwFiu+J6aDp4RBpDR5nRDL7q/ssSSRLZwnyf8h4GXV
XxHFndRIqG+W30quQBxyQ7B67xNn858KwWzFFw+pgEfGHcDRwIhdZBFBFmwsBU06
C7KcbV0f7tGuXTtJ8jfexjjWVy83lC6IiqxJZGHydPfNZXlBke4zpqCuJdJiSDhg
c/rBfV7In4MWwlSwY6hvWEFPs3SidSvDnqpKJ2ScgT8JRMQqtg9ifvz9tw5EWrTB
vqRWyPp8PUYqHN0fdAW+L8HFkIjmtgZKovbOWdy9iWdaHJ/guZLiLqDjM/PU3LSs
UZNiuUCU7AyA7xInEDmmRrv7AAAD0D/HlT0q8zNw5q89T4pB7wt5OemQrAa71EEL
+kKf9bWRRGX9ONcp2/RVE54BquKjHsp6PvXeR+9nOplYHCgJSGBUG61fQaPUe2qY
S8lGuQIABh7OT/yNcNyMiGczl9fXJ08OhJbd5FElr6AOTrksthRF2ocPyuEU9016
CIdPD5v2o+L1PmG1t3LhEQMdwgXjHUSNBNmEUq5ZzFdvD2cDyLbZ6vSbxq0vCOrZ
uv9Br1SvPmPOeXsYpKJpWzq0fR7XrtB2XaDg2Ww/CcVDKD7Fjargy0Oa+NzDJw1W
2HmUbkjkvZS1tNQdXp+5RVtR4HkJKrI4subtQ2LwwX5opTpNs5jI+5Le/Jcsycj9
K6zph/zi4uuLe3GpVu+rFNZDTVQTcgqGYf+0N9sGZnNPCMrAYMYQl7G/GLnGYBEz
TZERlV96b1wH4Nj25npIGRpbW/ftYw2MycbO+lNYmzi+c00L9Bdm2j2IkPm7jEt3
ftCYXR2vq1oqUzERTfkBWB6f0HpBLmtX3nVTei/RiaJFhSQ5Wc1VAr+7veHoCRFW
3IuV4PyL9tY9mOJnrqV8NymICRdXbg2f0yDxXu9wp6tTJUSMHOy3WT8IZEoDlBJx
L8BK71CFLofxzFA33v+ds1gFZFitoxoYlJWG/n/wTZkwbN3JgvZymvXhJzjYV4Bs
nhL84UTuUMGXQoVcus0yxsP2F4IEui0+XT6nGd551B7NS3CRfQr59qGZbuOAVOHv
J4w/SEEpysnbCKloKn1mfcDPh3X6lQuI40BhD1R5XO/c8tBy5JTOlyyOS354Z/aG
PPFt+bFITSkYBrrs7p5lCDblhUDaMSqZ8BpLgYJhGFeWNAkCKAkFyfwkHdCWbLUA
AiW/arXuOULMLBGVyK9QojVzivUOBU7Zw3gwIKkxJfFFlRYv+9BIb19v22FbPbMQ
LZHmP2o+MQRUm3B7F1EdXiLvG+gZGYGBx2EDuRQ2B1W77NtAtD9iHNms/jNy1zlJ
lxd9TYYRNVsN+AE6VUotarnbN8P+KB8BecYfDi/Dnk2tAK9IbeAHDt/fIJcjQjAR
52uztU1i6xDv5CtKCDKVrHli+wVpBv/MMhDDBLV8ZeeHNlEwNktsPrdy6H+SURGv
A6mR+vu0XHPsnpHPnOAiWPh3JXvK1HguHeii4Z/Ey8YXfO2LZhYQBlaPgqEH3j1M
doyNN8XhiFgfrWxv+K5GWoDfDxZI322pWczQVDClwDOwR1OnUKE8wz2iFSK8oCtT
1XYy4Wp/UrxDyZB1crh4y5YlxUR54l4yxMZLw5wagZM/jQHABks=
-----END OPENSSH PRIVATE KEY-----
`

var opensshpubkeyEn = `
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsUGub8db33AsanqRw4wmwFiu+J6aDp4RBpDR5nRDL7q/ssSSRLZwnyf8h4GXVXxHFndRIqG+W30quQBxyQ7B67xNn858KwWzFFw+pgEfGHcDRwIhdZBFBFmwsBU06C7KcbV0f7tGuXTtJ8jfexjjWVy83lC6IiqxJZGHydPfNZXlBke4zpqCuJdJiSDhgc/rBfV7In4MWwlSwY6hvWEFPs3SidSvDnqpKJ2ScgT8JRMQqtg9ifvz9tw5EWrTBvqRWyPp8PUYqHN0fdAW+L8HFkIjmtgZKovbOWdy9iWdaHJ/guZLiLqDjM/PU3LSsUZNiuUCU7AyA7xInEDmmRrv7 user@web.com
`

func Test_ParseOpenSSHPrivateKeyToInfoFromPEM(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    newSSH := New()

    info, err := newSSH.ParseOpenSSHPrivateKeyToInfoFromPEM([]byte(opensshprikey))
    assertError(err, "ParseOpenSSHPrivateKeyToInfoFromPEM")
    assertEqual(info.CipherName, "none", "CipherName")
    assertEqual(info.KdfName, "none", "KdfName")
    assertEqual(info.NumKeys, uint32(1), "NumKeys")
}

func Test_ParseOpenSSHPrivateKeyToInfoFromPEM_And_En(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    newSSH := New()

    info, err := newSSH.ParseOpenSSHPrivateKeyToInfoFromPEM([]byte(opensshprikeyEn))
    assertError(err, "ParseOpenSSHPrivateKeyToInfoFromPEM")
    assertEqual(info.CipherName, "aes256-cbc", "CipherName")
    assertEqual(info.KdfName, "bcrypt", "KdfName")
    assertEqual(
        fmt.Sprintf("%x", info.KdfOpts),
        "00000010238fa411ee0b4c84270bd2135523b1b500000010",
        "KdfOpts",
    )
    assertEqual(info.NumKeys, uint32(1), "NumKeys")
}
