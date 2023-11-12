package pkcs1

import (
    "bytes"
    "strings"
    "testing"
    "crypto/x509"
    "crypto/rand"
    "encoding/pem"
    "encoding/base64"
)

func TestDecrypt(t *testing.T) {
    for i, data := range testData {
        t.Logf("test %v. %v", i, data.kind)
        block, rest := pem.Decode(data.pemData)
        if len(rest) > 0 {
            t.Error("extra data")
        }
        der, err := DecryptPEMBlock(block, data.password)
        if err != nil {
            t.Error("decrypt failed: ", err)
            continue
        }
        if _, err := x509.ParsePKCS1PrivateKey(der); err != nil {
            t.Error("invalid private key: ", err)
        }
        plainDER, err := base64.StdEncoding.DecodeString(data.plainDER)
        if err != nil {
            t.Fatal("cannot decode test DER data: ", err)
        }
        if !bytes.Equal(der, plainDER) {
            t.Error("data mismatch")
        }
    }
}

func TestEncrypt(t *testing.T) {
    for i, data := range testData {
        t.Logf("test %v. %v", i, data.kind)
        plainDER, err := base64.StdEncoding.DecodeString(data.plainDER)
        if err != nil {
            t.Fatal("cannot decode test DER data: ", err)
        }
        password := []byte("kremvax1")
        block, err := EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", plainDER, password, data.kind)
        if err != nil {
            t.Error("encrypt: ", err)
            continue
        }

        if !IsEncryptedPEMBlock(block) {
            t.Error("PEM block does not appear to be encrypted")
        }
        if block.Type != "RSA PRIVATE KEY" {
            t.Errorf("unexpected block type; got %q want %q", block.Type, "RSA PRIVATE KEY")
        }
        if block.Headers["Proc-Type"] != "4,ENCRYPTED" {
            t.Errorf("block does not have correct Proc-Type header")
        }
        der, err := DecryptPEMBlock(block, password)
        if err != nil {
            t.Error("decrypt: ", err)
            continue
        }
        if !bytes.Equal(der, plainDER) {
            t.Errorf("data mismatch")
        }
    }
}

var testData = []struct {
    kind     Cipher
    password []byte
    pemData  []byte
    plainDER string
}{
    {
        kind:     CipherDESCBC,
        password: []byte("asdf"),
        pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CBC,34F09A4FC8DE22B5

WXxy8kbZdiZvANtKvhmPBLV7eVFj2A5z6oAxvI9KGyhG0ZK0skfnt00C24vfU7m5
ICXeoqP67lzJ18xCzQfHjDaBNs53DSDT+Iz4e8QUep1xQ30+8QKX2NA2coee3nwc
6oM1cuvhNUDemBH2i3dKgMVkfaga0zQiiOq6HJyGSncCMSruQ7F9iWEfRbFcxFCx
qtHb1kirfGKEtgWTF+ynyco6+2gMXNu70L7nJcnxnV/RLFkHt7AUU1yrclxz7eZz
XOH9VfTjb52q/I8Suozq9coVQwg4tXfIoYUdT//O+mB7zJb9HI9Ps77b9TxDE6Gm
4C9brwZ3zg2vqXcwwV6QRZMtyll9rOpxkbw6NPlpfBqkc3xS51bbxivbO/Nve4KD
r12ymjFNF4stXCfJnNqKoZ50BHmEEUDu5Wb0fpVn82XrGw7CYc4iug==
-----END RSA TESTING KEY-----`)),
        plainDER: `
MIIBPAIBAAJBAPASZe+tCPU6p80AjHhDkVsLYa51D35e/YGa8QcZyooeZM8EHozo
KD0fNiKI+53bHdy07N+81VQ8/ejPcRoXPlsCAwEAAQJBAMTxIuSq27VpR+zZ7WJf
c6fvv1OBvpMZ0/d1pxL/KnOAgq2rD5hDtk9b0LGhTPgQAmrrMTKuSeGoIuYE+gKQ
QvkCIQD+GC1m+/do+QRurr0uo46Kx1LzLeSCrjBk34wiOp2+dwIhAPHfTLRXS2fv
7rljm0bYa4+eDZpz+E8RcXEgzhhvcQQ9AiAI5eHZJGOyml3MXnQjiPi55WcDOw0w
glcRgT6QCEtz2wIhANSyqaFtosIkHKqrDUGfz/bb5tqMYTAnBruVPaf/WEOBAiEA
9xORWeRG1tRpso4+dYy4KdDkuLPIO01KY6neYGm3BCM=`,
    },
    {
        kind:     Cipher3DESCBC,
        password: []byte("asdf"),
        pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,C1F4A6A03682C2C7

0JqVdBEH6iqM7drTkj+e2W/bE3LqakaiWhb9WUVonFkhyu8ca/QzebY3b5gCvAZQ
YwBvDcT/GHospKqPx+cxDHJNsUASDZws6bz8ZXWJGwZGExKzr0+Qx5fgXn44Ms3x
8g1ENFuTXtxo+KoNK0zuAMAqp66Llcds3Fjl4XR18QaD0CrVNAfOdgATWZm5GJxk
Fgx5f84nT+/ovvreG+xeOzWgvtKo0UUZVrhGOgfKLpa57adumcJ6SkUuBtEFpZFB
ldw5w7WC7d13x2LsRkwo8ZrDKgIV+Y9GNvhuCCkTzNP0V3gNeJpd201HZHR+9n3w
3z0VjR/MGqsfcy1ziEWMNOO53At3zlG6zP05aHMnMcZoVXadEK6L1gz++inSSDCq
gI0UJP4e3JVB7AkgYymYAwiYALAkoEIuanxoc50njJk=
-----END RSA TESTING KEY-----`)),
        plainDER: `
MIIBOwIBAAJBANOCXKdoNS/iP/MAbl9cf1/SF3P+Ns7ZeNL27CfmDh0O6Zduaax5
NBiumd2PmjkaCu7lQ5JOibHfWn+xJsc3kw0CAwEAAQJANX/W8d1Q/sCqzkuAn4xl
B5a7qfJWaLHndu1QRLNTRJPn0Ee7OKJ4H0QKOhQM6vpjRrz+P2u9thn6wUxoPsef
QQIhAP/jCkfejFcy4v15beqKzwz08/tslVjF+Yq41eJGejmxAiEA05pMoqfkyjcx
fyvGhpoOyoCp71vSGUfR2I9CR65oKh0CIC1Msjs66LlfJtQctRq6bCEtFCxEcsP+
eEjYo/Sk6WphAiEAxpgWPMJeU/shFT28gS+tmhjPZLpEoT1qkVlC14u0b3ECIQDX
tZZZxCtPAm7shftEib0VU77Lk8MsXJcx2C4voRsjEw==`,
    },
    {
        kind:     CipherAES128CBC,
        password: []byte("asdf"),
        pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D4492E793FC835CC038A728ED174F78A

EyfQSzXSjv6BaNH+NHdXRlkHdimpF9izWlugVJAPApgXrq5YldPe2aGIOFXyJ+QE
ZIG20DYqaPzJRjTEbPNZ6Es0S2JJ5yCpKxwJuDkgJZKtF39Q2i36JeGbSZQIuWJE
GZbBpf1jDH/pr0iGonuAdl2PCCZUiy+8eLsD2tyviHUkFLOB+ykYoJ5t8ngZ/B6D
33U43LLb7+9zD4y3Q9OVHqBFGyHcxCY9+9Qh4ZnFp7DTf6RY5TNEvE3s4g6aDpBs
3NbvRVvYTgs8K9EPk4K+5R+P2kD8J8KvEIGxVa1vz8QoCJ/jr7Ka2rvNgPCex5/E
080LzLHPCrXKdlr/f50yhNWq08ZxMWQFkui+FDHPDUaEELKAXV8/5PDxw80Rtybo
AVYoCVIbZXZCuCO81op8UcOgEpTtyU5Lgh3Mw5scQL0=
-----END RSA TESTING KEY-----`)),
        plainDER: `
MIIBOgIBAAJBAMBlj5FxYtqbcy8wY89d/S7n0+r5MzD9F63BA/Lpl78vQKtdJ5dT
cDGh/rBt1ufRrNp0WihcmZi7Mpl/3jHjiWECAwEAAQJABNOHYnKhtDIqFYj1OAJ3
k3GlU0OlERmIOoeY/cL2V4lgwllPBEs7r134AY4wMmZSBUj8UR/O4SNO668ElKPE
cQIhAOuqY7/115x5KCdGDMWi+jNaMxIvI4ETGwV40ykGzqlzAiEA0P9oEC3m9tHB
kbpjSTxaNkrXxDgdEOZz8X0uOUUwHNsCIAwzcSCiGLyYJTULUmP1ESERfW1mlV78
XzzESaJpIM/zAiBQkSTcl9VhcJreQqvjn5BnPZLP4ZHS4gPwJAGdsj5J4QIhAOVR
B3WlRNTXR2WsJ5JdByezg9xzdXzULqmga0OE339a`,
    },
    {
        kind:     CipherAES192CBC,
        password: []byte("asdf"),
        pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-192-CBC,E2C9FB02BCA23ADE1829F8D8BC5F5369

cqVslvHqDDM6qwU6YjezCRifXmKsrgEev7ng6Qs7UmDJOpHDgJQZI9fwMFUhIyn5
FbCu1SHkLMW52Ld3CuEqMnzWMlhPrW8tFvUOrMWPYSisv7nNq88HobZEJcUNL2MM
Y15XmHW6IJwPqhKyLHpWXyOCVEh4ODND2nV15PCoi18oTa475baxSk7+1qH7GuIs
Rb7tshNTMqHbCpyo9Rn3UxeFIf9efdl8YLiMoIqc7J8E5e9VlbeQSdLMQOgDAQJG
ReUtTw8exmKsY4gsSjhkg5uiw7/ZB1Ihto0qnfQJgjGc680qGkT1d6JfvOfeYAk6
xn5RqS/h8rYAYm64KnepfC9vIujo4NqpaREDmaLdX5MJPQ+SlytITQvgUsUq3q/t
Ss85xjQEZH3hzwjQqdJvmA4hYP6SUjxYpBM+02xZ1Xw=
-----END RSA TESTING KEY-----`)),
        plainDER: `
MIIBOwIBAAJBAMGcRrZiNNmtF20zyS6MQ7pdGx17aFDl+lTl+qnLuJRUCMUG05xs
OmxmL/O1Qlf+bnqR8Bgg65SfKg21SYuLhiMCAwEAAQJBAL94uuHyO4wux2VC+qpj
IzPykjdU7XRcDHbbvksf4xokSeUFjjD3PB0Qa83M94y89ZfdILIqS9x5EgSB4/lX
qNkCIQD6cCIqLfzq/lYbZbQgAAjpBXeQVYsbvVtJrPrXJAlVVQIhAMXpDKMeFPMn
J0g2rbx1gngx0qOa5r5iMU5w/noN4W2XAiBjf+WzCG5yFvazD+dOx3TC0A8+4x3P
uZ3pWbaXf5PNuQIgAcdXarvhelH2w2piY1g3BPeFqhzBSCK/yLGxR82KIh8CIQDD
+qGKsd09NhQ/G27y/DARzOYtml1NvdmCQAgsDIIOLA==`,
    },
    {
        kind:     CipherAES256CBC,
        password: []byte("asdf"),
        pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,8E7ED5CD731902CE938957A886A5FFBD

4Mxr+KIzRVwoOP0wwq6caSkvW0iS+GE2h2Ov/u+n9ZTMwL83PRnmjfjzBgfRZLVf
JFPXxUK26kMNpIdssNnqGOds+DhB+oSrsNKoxgxSl5OBoYv9eJTVYm7qOyAFIsjr
DRKAcjYCmzfesr7PVTowwy0RtHmYwyXMGDlAzzZrEvaiySFFmMyKKvtoavwaFoc7
Pz3RZScwIuubzTGJ1x8EzdffYOsdCa9Mtgpp3L136+23dOd6L/qK2EG2fzrJSHs/
2XugkleBFSMKzEp9mxXKRfa++uidQvMZTFLDK9w5YjrRvMBo/l2BoZIsq0jAIE1N
sv5Z/KwlX+3MDEpPQpUwGPlGGdLnjI3UZ+cjgqBcoMiNc6HfgbBgYJSU6aDSHuCk
clCwByxWkBNgJ2GrkwNrF26v+bGJJJNR4SKouY1jQf0=
-----END RSA TESTING KEY-----`)),
        plainDER: `
MIIBOgIBAAJBAKy3GFkstoCHIEeUU/qO8207m8WSrjksR+p9B4tf1w5k+2O1V/GY
AQ5WFCApItcOkQe/I0yZZJk/PmCqMzSxrc8CAwEAAQJAOCAz0F7AW9oNelVQSP8F
Sfzx7O1yom+qWyAQQJF/gFR11gpf9xpVnnyu1WxIRnDUh1LZwUsjwlDYb7MB74id
oQIhANPcOiLwOPT4sIUpRM5HG6BF1BI7L77VpyGVk8xNP7X/AiEA0LMHZtk4I+lJ
nClgYp4Yh2JZ1Znbu7IoQMCEJCjwKDECIGd8Dzm5tViTkUW6Hs3Tlf73nNs65duF
aRnSglss8I3pAiEAonEnKruawgD8RavDFR+fUgmQiPz4FnGGeVgfwpGG1JECIBYq
PXHYtPqxQIbD2pScR5qum7iGUh11lEUPkmt+2uqS`,
    },
    {
        // generated with:
        // openssl genrsa -aes128 -passout pass:asdf -out server.orig.key 128
        kind:     CipherAES128CBC,
        password: []byte("asdf"),
        pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,74611ABC2571AF11B1BF9B69E62C89E7

6ei/MlytjE0FFgZOGQ+jrwomKfpl8kdefeE0NSt/DMRrw8OacHAzBNi3pPEa0eX3
eND9l7C9meCirWovjj9QWVHrXyugFuDIqgdhQ8iHTgCfF3lrmcttVrbIfMDw+smD
hTP8O1mS/MHl92NE0nhv0w==
-----END RSA TESTING KEY-----`)),
        plainDER: `
MGMCAQACEQC6ssxmYuauuHGOCDAI54RdAgMBAAECEQCWIn6Yv2O+kBcDF7STctKB
AgkA8SEfu/2i3g0CCQDGNlXbBHX7kQIIK3Ww5o0cYbECCQDCimPb0dYGsQIIeQ7A
jryIst8=`,
    },
}

var incompleteBlockPEM = testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,74611ABC2571AF11B1BF9B69E62C89E7

6L8yXK2MTQUWBk4ZD6OvCiYp+mXyR1594TQ1K38MxGvDw5pwcDME2Lek8RrR5fd40P2XsL2Z4KKt
ai+OP1BZUetfK6AW4MiqB2FDyIdOAJ8XeWuZy21Wtsh8wPD6yYOFM/w7WZL8weX3Y0TSeG/T
-----END RSA TESTING KEY-----`)

func TestIncompleteBlock(t *testing.T) {
    // incompleteBlockPEM contains ciphertext that is not a multiple of the
    // block size. This previously panicked. See #11215.
    block, _ := pem.Decode([]byte(incompleteBlockPEM))
    _, err := DecryptPEMBlock(block, []byte("foo"))
    if err == nil {
        t.Fatal("Bad PEM data decrypted successfully")
    }
    const expectedSubstr = "block size"
    if e := err.Error(); !strings.Contains(e, expectedSubstr) {
        t.Fatalf("Expected error containing %q but got: %q", expectedSubstr, e)
    }
}

func testingKey(s string) string {
    return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY")
}

func testKeyEncryptPEMBlock(t *testing.T, key string) {
    block, _ := pem.Decode([]byte(key))

    bys, err := DecryptPEMBlock(block, []byte("123"))
    if err != nil {
        t.Fatal("PEM data decrypted error: " + err.Error())
    }

    enblock, err := EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", bys, []byte("123"), CipherDESCTR)
    if err != nil {
        t.Error("encrypt: ", err)
    }

    if len(enblock.Bytes) == 0 {
        t.Error("EncryptPEMBlock error")
    }

    if !IsEncryptedPEMBlock(enblock) {
        t.Error("PEM enblock does not appear to be encrypted")
    }
    if enblock.Type != "RSA PRIVATE KEY" {
        t.Errorf("unexpected enblock type; got %q want %q", enblock.Type, "RSA PRIVATE KEY")
    }
    if enblock.Headers["Proc-Type"] != "4,ENCRYPTED" {
        t.Errorf("enblock does not have correct Proc-Type header")
    }
}

var testKey_DES_CTR = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CTR,FF234E7A492EF147

95VoY+f+oWf5OTIcyBiemd1Jy3v7LLRkPuBR3XhCbxxxCSNoZFoTG2fBeEUWvjfG
QZoZPfNwpUcuEb4NxRd5Mx4F3yb/54sBBB+LASdPM3Qp5eZ5sCUL1GKAO7RYHHAQ
hffU2n0Y23yr4kTlyj64MZvFUjsZRJ81wDZ0XnPc+ZXj983RZKU0JfBE4aKEP85S
etFLV1RcyQ/rpeMXDI9h+UW9B7cBVXv06PrpIMDgKJL+JGO29iBtKU6fbBsZi5IA
NIEqVJqgCW4K4KX/H2UNXREgsiJ/BGjauK6XtTUHcCfQfsxpo6FnmcB3yD/Dp3Co
knkXGbSYVEuukyK6f/BH4IPGtgRiqCrpRBziVtJx9DT1T0qgIRGLujSlr9cvMufl
I+n1tUlTxstjVxptxup+4Cfx1hWSBRIWFO2KX8q7zRhLZ5uVVugFYQ/0XL3Kz5Uv
gKE1NStuk/kc9C1T0c/P+WbBYI1Lx9LH76eJXruj2y7az189DjCsDbR+gIMirzcX
ZE67FRO79lZFy0NckHwhtbZ+4TR1bBEuLGmEfsXI0jhdnatpXC0pIAlJt3oLbjHS
qLKdU8fcyKbP1nbCMmUjALXJMIEkvc0WKkHY9gu0CcyNfTkTGgsyptG+B1TTU6il
EltrJrbDG1XEmnG8m64wFDXGNfohCgj1hRPG0uvMdMDzyYCONkFva5jTqLIj96AM
54CyCh+l8/GJytSen2BBV0yklHF5xVQpJE3XlJobSWFd8V5A1l3GbTpsJ/9p2HXC
11XWP9ztWYZ7kooXn2PXqkXxNuGPu/jj/NEjOkkV7A4=
-----END RSA PRIVATE KEY-----
`
var testKey_DES_OFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-OFB,B7A34B2630AC0335

V1R2CVqxohGuAwdx2ajaqCcih1skaCmw3WXqqKN3O46Of31SCCuELF+2GJ1bZmE+
aTk7l5kwCIPiGuELArIAV9iVJjJV3hhZ3lI29XtffxdQ0rtJmxWM53ta0UzYGyIz
jMcdmtBDh/emG5sqjandTih9yISaDhDycSB/UvQmgj5aBTKjJFYIJrRFfBox/5NF
zUSkkMJoEiB4kvYS8l51HJsii9c5aPEIzSbU5bmeopY0jRMNa74ruSsEBvg3/pLr
uJsBaALrdo/MeBU6LPGfInoCS7ySB2dPRlo0ONr3xDRPrXZJ0/GFCyo52vx6/PTf
gxeln5z+UYTKStt0Ub7TiyJwMSj4rTSkldeFU8f3H2ypNZoB1grzd0rgtINcMymQ
dc90Q9ATSGV2DnRzUzKkhn55oXzGXcIVqWweg4bkbtzxo+jmOchXATnrd/gWxWz3
vsDzl/67eQpCSTal/MKyQcGBD9DqzGiQYDdtKwoCDeJLhZ7Qhc0OPaqfZ8s8N/DX
bV1s6b1U906+kBHFVaPoVBug+mqzrZbd+VQg3AwemDCL5LxEf6oN6t8aFU2fNTzU
VHsyX/eZqlg7S4ftAkoHEdLGlSK0TcuARcpKmclw9wXxZdjHOSIt49nbI/OZ1xfS
Zm5dQsnkLbPK2bKALSKQfxT/RdY9V9DYKtd/OcwRssvXY+CzKPLtNbkDmicn2ucD
4fAS8FiOOzxzUwlvtuk15rznVb7D3gUm2s1k1yRk3TY78zVlMB0sjZrzsMgkvM4b
nBoLwopS2CKwWv1ttXjXY0EjRz16oR57qAjr9WIQ6v4=
-----END RSA PRIVATE KEY-----
`
var testKey_DES_CFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CFB,CD26768816AB735D

Nsc+eYba+4fWQuSC7vXOxw6tN4w7z9ODF9MRtO4E+0S0pV3NXHY/l/xvW9ljrGuc
3hmUKOtZ/EQbAhSZo7KyTJFbc8qbOyloag0dumwblC2qdXJYTOZat3LtaqvJ/4fJ
DVeHgYJZd17NOjh7KLS+Vr9alaua/3rAN6z7Trdc3EXcokN+h1iucg8WpzNmh7gp
ql1d8fW9EXJ0QZlH/QWQcNw6GltZ4VSbshdsUQli3f7Lsx18maMDLPnaFsUfrd3I
ePAjxTrmgsIjNafLXuYNpoESEHnPm6oPGOJBjl9e4SJqNE+yDecvIZUkkH7QiCZl
Nn/oe6RsY3mjcLpRvRhaaxQgsc0uNeSFeeLg1WsXgNDBmjWHydglsuo0PsUUxMTm
qx8fZU0yCJ5RcrrLFZcSjxZfs8RixQdElZA7VvtoomsC3K2pQJJF9ASWYVKTQQY5
nQfgGAxdwPe9z/59TMKghaW7Sq7/NEtvA4SxGxoAW/qGcbRsI0UuqIX41SQoJeiL
9yPW28r9xrNH7UXLz9cqYXsarHTVpOiKh8JnnVHzRidojC+Qoa31qBChlZl+kmuR
6XALOGm2abiaY6LzeWlb92ewS679w0fUSbi872WDafrhBdULqxguBmrlVf7zUjQL
hawM4n2mXnqGLYH0BwqiCCjiWVJyb674T2ggoJCsi5MT0M2DhldLQlRwfvoDB+Kg
A4A/aHB+V5eDqTG/UnO3UIvpx8vr7Oox2If3wc3b2mTiEAWY0AYOOiSagTOW9HLu
HV9LrrqQxBwWHEZkFurDUvA8Yw5n+D6xsag8y1JNOVOVfw==
-----END RSA PRIVATE KEY-----
`

var testKey_3DES_CFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CFB,D2C6635FFF7A4DE8

zhWXrCEVN+5fptlVImtQ/LPu0qI1ox7h7ZL//vRyp0wLnTSBbP8y5Oo8fzTmvDvm
y32CMUuCL0P5qzb+Ku3Sf8ibHicoDTZ1RtogSLVY1RImkVtI2hy6eiiyOLfryjaA
mQ4eSQ6FDkoCxXgFj1LzmNvECtTXbNzfkbdQ2TjE4AiNYTd9MSzcAHO1ASANFDlS
KYbA7QS4DIVJGdpngWUOhr0DoHq3IhNkU4it8j6qGr6l8fLw/wo+tgOAJqTd+aaL
zvZWL85h/ZgVxIZlC1E4eW+YiN/YZxPQ6pbPe3KeGzY7GNmdr7QBST9FFLZD9meE
7FZhq6b6Lef/zvEDWkJgegyUefgPdNg65IeMjMuToQsI8B0CofwkvLI63wqJFKvV
n9ukVNYzy4GJrlWNamtKpC+krz6kjW9aPZAAeMrHQzzvGbhDHs8xghd5xsGZ3nup
DtD0vlqcV/FlJvmJkeDw4BF/i3ybUdG0PsyGdEoxXsl7UpSzlG8bBSOidGtEb86o
JFtBOJnv8sALLpo0dIsu4n498Itd1ngsTEWIh+7BxQYL7yS+e+nFD8CMr1XZI2yY
HxmJ7NPk39ZEr8IIzmOwWyrR7MgC5svycx/49vFekazyO75ctxPqI4ZLkHeH2yvp
nMOlEKQaSiXRxcE9Zz197W1xFJZOF7oSvF+Ih3F4auvJcJzLk8RfvYgmAV9FJT8n
o15yE9naANp/ml1ZmFybky8cGpTYA7WTiu16PuApj9sMpfZLJjITBvvkAqccYiBt
mcOQ5xdAyTvovTQR4mxbe/SwsBtseICI7OnS4nHRcdEWcg==
-----END RSA PRIVATE KEY-----
`
var testKey_3DES_OFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-OFB,A0D9A77A7948C56E

s+3F7lzcV6Qzp1DIrunvfmioizqAo/xp7c26amLJ3A1tZd3CUqdB2VEy+MMpsulQ
0FyyBRG4z7kjONSp7rmrjtmc4xOulWj/LLovhjQKF4TfhW1QosYReuEwVnlEneTC
zEtoq1hYWHy6KC61DK4apG5kZivuYk7R7iX7yAzBieme0PoXGHoLw3mIMEb6XQcM
MOrgimZEFsqJpOuLu4+E0asfJkW3faDwgp6llW1/ec+/qJCdsXqePLjJtR7hxjJq
TZrAwqMfkGY76547ZWLbR0yuBMTc2e8jVrM7OOm3iUOcafz2WXC8JVCwYpuys8x3
CJXlA9bytm0hGMqRE2HfmAkircHqAMMfiw4l9x1RGjU6jAxq6v5atgwFWt5/LFen
nZCebQxF2bM13nHRJmft3kYtjjH/ufA3rUl80tTvXlN+fy+9G8/ylFoNDUDn2syj
FUia2VdNQ7ddH5uWx4CDOnKwcgmsX8vUoi2j0mBOwERELMg+P5YhmuyyWlC0eK4T
8sG++teRpFpE+jOpXVNnGw26l/rEgXDfe43XGnQH/9a/L6NLeT+RJWnsEpkwHph3
g344ArmKA98JDqBCdUk3ROQPsAlbY5OAAXe8r0YImmxXnqEbkWqyRNEoBt6Sh5bJ
WQhCMsnmZoHmDgPqhrfi+H672MEQdN8SngItDCv1NGp60jvpW3VbqW25GKVy4VKc
awEw/CQpPQ7E2rF0YmWVOXZkWcnRXcY6TBcTjKvZqsjcvJAIOFw0NQy6V69Mgu53
nMXfIRLAvuBgtv2zcwdbgsvhAHOeV1d7l1EuISNRkBRx
-----END RSA PRIVATE KEY-----
`
var testKey_3DES_CTR = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CTR,140F4C905495A783

tfS0emYpmj4oggZbRntqambp6eUCpppo9W4xdoOOi3Ch4Jgb8P+9SD+Qq661qocU
hQkLYWIpgto/E7iBqg/aobsY5GTYNH4dU4mcRxicv2F/joShXMkmBjfQHNy+mDWJ
nEEXAh7FjcYvxaZfvepmlwhWvsTgSo/IzBr3sCzrPr4icUJDBPx8w5/xlAFGDJAU
o4yH0kUa8MeJ1/RWOxN5nDVEt3jvnOsk8NDkQt3LPLgU3OR7S4nR2JLeaz0BGaUk
EsXo2muk2937GGWm9YfuqDeuic2QG9R3qLuCR0jYZ0rXCpU09McFzZa0geXiquZp
3VbCJucODP9x5dhqLKL4KHx8XqVRSgadhrSnxQTHPa124O6jEEtuA0eUGONYV5Uh
pEGng8f1LjJmlVq1qEDPUsjrgp0WkvV1CgwbHeWspQA+eUteYTqpYj7DHDjwcxC+
zyqkl6hMRFYTrT3RnaEgg2DWo/Mk6HhMMJyo6a+5wYsCyb5rk+iwfjSFj6jun7E5
rE5sJ5XVDA2PSN9yy7miUcty2R263+WvBf2EC6I+WrIta8m8xVS4BIjYVMoqi9fl
iX2Uhqbhx24YhNdUt8qFs3XyVqpk0fbtDlKc8yYkSwme8SquGZzoei2pf76I6GJB
DcWQkAVeV0rN8U1U9H1sGC/EBaxCDQYrvcqacQv0iU7Xe6Uf/9qkmWBc6maq9AFP
mSHYIoYDhxtZTPdfVo7JywEtujkgeFPG/6vpomarWRy8dAcUnLUct3BZb8lD55et
OmYAMAJyodew+6ZbTG3LRiyIH66NYGCU2Yhspd4ZeCc=
-----END RSA PRIVATE KEY-----
`

var testKey_AES_256_CTR = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CTR,04CDB0482386CB0D79252DD7F8631C83

yD4lgEiGu5U8vagEgFmP/9vdymil46KCljonxyKSjTwbeipByzZYr4WodE3iH6p1
Z5Wa3DHxEfmkRd9JfwQyOyo42HNYq+GELBL22o9vktswADulcR9KymW1TbdwRZot
gfU9DBT9dNPB2FjVS7sSkR8JBbHqLb7++UNs5eTmI+NGrARsSAdIEjkFs2uUvinB
CfztjQAGJM+3SSJg70lFOu8XtiqiRJo4U9Yjm5y8Cb+fgFjeigT2FMHLVY/ZyD34
AJHxuk2TIgAjGLoIVYCe1FeGs1+TvKlq05IKpBh+vi2fFs4nI92jfuCcQEMH+oOV
ISbbjkoRhcA+g93ISM3jsg2g4OYQv3l/xKguIbo+gdboR8ehrBCoak+cM5hEsLEG
7hNtP3HF5VVc1tnciL8k9Rhw4JA0g7+cRALP/J8fMreh3Pe/h/HH1S4ipZGaSdCY
bxyKZRkzT8o3wXYHANJjWq4abyUFm3XffgSq0XVuOQIk0BvSVW/syLSdH6Ry/kWf
mFHX5VXAjnc0nhAE+ETcV6DSEm6k4SNIe+04OXfuUlSFuUGaZHMlK4Y6+a+OR+iR
EyLBUs7WE/FgdL06fXNR/oHl+OSqkqWfzsyWVUVq5vkeIuoeF54MzX5jd4HFCynu
hPCSMfnEdlhz5fmmmynOQGgDpCkyGJlhOJGJiDbjWa5g6JKdsfWEX2e7jh3Uo3TY
2nLmYjljf6CaQtHTKmD8bFQ6QPBGwboP1AV2tLis8P5x0QAl/2iZ78r7FhE/a492
ejV6+uGxoV4nH4VtDlQD5q0UszLStTrznZGgbI+h898=
-----END RSA PRIVATE KEY-----
`
var testKey_AES_256_OFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-OFB,06C6F3444FEEE2DC423F83FC8A45DEC7

PCqMsrWxghULrV3ctM4YOBrjUVPi0gcYWtXyXrHX47GugYKg8THjbAIJmeC/ntiR
1rEK7LpdW/3qMEX0CEwloppCdlRY72grBIhgzzPiyNBBSzlzrhVTe8/NN+B4zV7C
tD/Kgis/5j2NCyAKUnr0v5N5vEPeEaMDVigK+cOraev1jpd9+AMXPsn/HyiPCpW/
PF30F0RgaLz3RHNZEulkBXHApbW5elJbuXxzCOzw3PFmXRFVHixQR7/WR0iuWOUG
8t1vuXj9FZhl5HsJSI+cjNI5sMpympzb64iBZaqP5SqGkzKBkaunSWsoFZScNdyJ
51G6yuoA6bIijvQpfklgkfnEqfb6U5REnXXWokCQ3OSEpuTYkxkbZyFVF9Dp6bod
0GuirdfI8jMu8Zgm8iW6nAej5C7NvFugTg/bgxRBnUB9PdWNSLqJepBqpLvbGVcd
gIWx9dYeM0uC5oiElxiODcDxmIa/nokwLO4qoJBGgagyIwqCIqCzemuc4wcJlJ+j
L6PYrSvzh7fuSc57epzvaIIOQ+Z7PaIw4XEZi1KlEPm1ae32b/GqgkdUCmu1pKvX
3zO7U8XPiwDi75ryk7bwsZSHmggiBgFaqa4XmLC+cT/0/N0XwSdmoAfv+ls50yWi
aIMjPi9lMN79O+QuE4KjG8PfceTkONwV9REAIZh29WRlEFp4phYZbi8VI26lqebG
hvfD3e2TKrOWj04cG7IufCFqonZ+mOFvQnwzXtswLZI4nWifIwM0clkgiV8jZnWA
BXtOrl6JbjuAtbgYloRi472YWrNn4JyQx4XrfOHndNE=
-----END RSA PRIVATE KEY-----
`
var testKey_AES_256_CFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CFB,FEE6BA57503D765BC6D87BC6954A0D72

bq7Nbbr5BF8Me+OXceRQQAc/S3wcD6Q9XLQgHZpwulLkw780ooTU5C51d/4JmPcM
NZDo35EPjCG4jb2wEvdWItpn7nF3LMnTOvJfcpH03NbgNfbLgn+jvckkU1ehOPoi
UHgww/4jjEGeKRTefzbjxEg4rD2aRuxe34yR8GlCOR39UxdziIQytxPvRl/Ad184
+QeqFb6cW2MgMUPkAL/PA4H1TfSg6xCET5ewMhgHTTaE9sEmDYtlxCVEkhLTr21O
avMHvLgQS+iQrE4h3iJ9jvWWsUUYTIfCpNrN0dujClX/RPETfiNhUihHXasA//qh
+0wBh3zroF/+2TEYXwPOJyHBKULEgUBxm8mdSlHLf93mkMpYs6josC3XthpPzX46
P2nC2Pt7lzs5MRNIMlj4DWCODOzuDphUJ88Gt+g5SCOl05fqRka5Qy5vSWc3v6/3
UJI9yj+eNFF7d0TjW3saMF4m7x206q90LL2d3gN4hNA2a+yVTiUQ6/HIlAebffTh
RWptkznl0BSJkvUu+jon16KnPYQvuyFiI6KN1GUKL3a58OmfNljmNYyY9dOjjT0D
IrHJbDgyuwLcQ2WhafdTDWt5Zj2U1vh2GbkNAxQzljbDku3l5wvaJvSQSHK+k2uI
0pHc3RENOFZ751b7A+H23Y7V/Kqi9tWfCqFo0Ybdc8kah1a1+zyxSrq7FEhUG8ja
EJI6g3hykcWb6Xv6g4qCNxt93nTyPIxeJsOhCiValjJGT5DxzCGjcwWKh0xCTAOF
UR9uChIsW6/OIOevnvffncQoPNOLZx8XorAdD8ABtg==
-----END RSA PRIVATE KEY-----
`

var testKey_AES_192_CTR = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-192-CTR,7239E65AC7D2250A552554E778198DB7

nB8IXLlbAiLze4VRUgUCB1qvXNwWaZSBtZAZUKkWG5qSieg0kw5oWE1dPwHe1yFh
AziHy/G7Q66+UEEA7ZA363I1+m5cniCXJbpSUD/ta9MtZ3HM+MOtbx8/r2Xcrmio
pAzs5xYqW0dlHqL8v6mZfMYxkPFE+TIr3QJniNg/kNPAA9D8Se6MPvjYa6H1KIwI
0vM4LhyZJWANC3dqg8kntZLtXatHsPR8PEm/Pa6PQgcsMiku1g4+TyoY9k03DaR0
t4e8AcI2WQb6sfzBszEqt9zyew87ArA5SY6lL3VlP5chCcdNmWByVK57VVs5fTD4
wh4X6h8xF+D2D1hw89eCzFv5oPpD7IaTqWfsm7NFjD7zWp6NRO6lOjb9SSOuwKlh
28mmETUJuQnno7gVyZAos853r1L8sKaKAZFB6GGhZgFKQlHmMuCnMIEmWC/hrVMV
F8LVF67489JTM/j1h6LwfzOL15hAEnybyfDDlNY7o672SJqGEirX+uUUtoeo5trL
KykuBv8syC78IkpkZ0Q5JJ9PBqJE95AIc8rISMWGMhmj6jDU2lKwcx9Mjzwrm+R3
jwCt3AKt9XmT43+Zxvp52EbEmu5IFgDeCYi3oKByJy/nNZ4ZSanoaa/NZjYBpF0W
ZMv3mgsXjrlN2AEQhFk5U/jslo+6v5BZ9LF6Ef2q3SFmnaAA8uDh/vNlXUZfZHKl
9BeCVGynk7aTfVVBwPEv3LQvlFCTqBF4MMtuwl6mMCdgh8lT/4EJFgvVZ1pJMP+s
/gq9cuT2+i2nZx83WM5qrws6vxp6Upt+jzYkoPeJCn4=
-----END RSA PRIVATE KEY-----
`
var testKey_AES_192_OFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-192-OFB,FF7E37B3FEF59C5A65C41D1BEF794605

Qzr8S+Pgm6te7jMIYx3Hdg7gVy9ABeXL8KHpW9DhUBcWrVrfoefWCVnp6CRrXqo7
VU0qiXOzILNeo5GuujeMBU/vKhIFrZBMtM0Cb/CPbxwEWmvkCpdpz9/+EZrIH2kw
oAgXjWC6v5nkO9PQswY0nVPIUm35eYN4rZFyiRlOVVrb94nftkh8XodHEu+dndvj
xuplDO9FgJeDIpyvi23GElsRlrtalHSSjvdKKabuk5XNpdOUnvbn7hbmrdSauwHF
xY4ahm6Ld27FJMxMSLJkWCSCA28D5a0c/CMSFu7qp1zDyRcZrZ2rhBAUZAKcQt9J
jMgu7SLwhHcJNGraVq1BitGxB0O1fK2HbfhP78pbtRI86BiekPCaQnLOAniSm7qZ
5aF4RbU1M2kR39YuLu6ciW6Bg986sH9aoNIPKluK/sVpcqLxLMJx0yeBE4AU8HYC
NNds0tiiGYn2MDyhB0QNZRt5RyPUhmqDli/POq58S420Et7MTItbCI2X9nRyoWJb
01XOtWUecefao/+8qZBs27gR1BSESsXW+d4xegXPoaxmdtSPF7zy+jkmk7Re9rtV
McwotMjIhw1f4Pgc0cKnnVSn2tCDrU7k9XV5SnTcyVwVatz7ThoBF/vhGHdBK+wz
q9GmPx/l/RZpm2syG4rvd8Ofe+rlp00/KyGWF/TQpI5CcYOk9FWTYmcr6fxJzfC7
PhPj4+q8LxTGveaZpg+tLGnm1o7tGviM41evjPE1EvIFCGyqfGmY4vf1Rq51vCbZ
El4w67K9Awvy1pAK+a4NwAckjDXJxN4nWO8k5260ZBIy
-----END RSA PRIVATE KEY-----
`
var testKey_AES_192_CFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-192-CFB,55C7F8A07BB8292823213057B20F1068

s0resB85a6gc5nFU6iIoN3eC6lGycjL4qyU7/oc/KIfnwRIqnLGCgdds1ZQUu6P7
Ju0WcWf35A9PWCBVDCbvI1aavBFmkKoeVT75vQl294wMUR83Msh8BUd4EmBAOMNb
u/PkYVduPeIhT1JvyW3+O2ZW7MJ8YnpJZ8jlNsmha8th5wc4aedOHDG6bJfFiMXX
Jnqq9fKHRqImZYSuLoqkwWGCvYPkzGvroqf2ZbR/HWj0qK5BpOderxJ0OXYlv3cU
qMwEeMIRr8pdrvmplYPihRlPCZwcMoU3Ksv+e8oLBu8Ub5XIqJwhDs92LXu9Hvam
Jh+mtURFTmX0z4QNa5u2yOAfckeyEbWhR5kbbPjpSVxOaMjSkb1tNd31uNRcrwDY
fhBKln/nUUASPcE+y6QH2f6FVezd0XLXD0s28/3RqMKuKdheIPgX6ujt3/BYPBfQ
FsbZqaP10VjUOtfyTnv7dU2s+PNZt3Z6/mqojH7s9lb+WVDkGwzyFSrXMZOte4Uu
lDdUlhG82pfRtimuoMfcFd7kiL4qQTOlgQMSiBOMEN8r26S1hTfeAebQsr09ZG71
dJC7ERMn6Yt5S88TPHSF/OdjCEsPF1aLazygSjSwhoACX7g7045afZvBQ89kNjuQ
8VZfsBE/rXv8zfBhsvqXovWnxLT8Zc1IDdBAqHWIRPHnd34n+me/GIC2lbQTFU9I
p683q/nFSaqxkWFpNC3ituZ8N6Df95mlP6zOHL0CpqUthqxkBqv1BGT75CNrQ2th
KzyqVofSD5f7x4RlH4XBFLDyItcpNjytcnLbdRiBuLg=
-----END RSA PRIVATE KEY-----
`

var testKey_AES_128_CTR = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CTR,1098F6615FF76BBFC36D6AB8DCF536C4

Ecrm0MZ03G2JGHAUt4sDL4ayiuCYzGsmKl4v4gLnuUcF2/LExs2HMWTjvEWlglvl
LqSW4MyAyKyga1QLTmlAWBHT35WWVPHaHZP4bYBs78+KKdaOtI4RLRCHs2jVla4Z
a2PrpSQA0N8HbVPtvqnamPEh/Oyz+qv0VxsYhRcPiVdLsGll8MMSxJRW7ihblOwJ
yhLE5uM9HDD+2oPoIsreqdvP3tNCsMCI761YItcX56e1Vj70FvFrowLQVCvIeDP2
acwMTUehbVv6PpOSKCvNgs09uX0rHkIJ2gpU1Xux7ChMNBBfdDeWSHW2OonShB0l
sceSb/fLwlXwivdeVzwDr8Jlr/u8f7TkawqMXQI7ummhY3bvYyyhrhX8rZTTsY4A
KYGopPxku5yv9EMPWkXbu8EHUSpXJxGU4FBWsim6iVqKk+qbEzjmddX5KVm2Xvk7
qwbQZQ8JjKfPipTHzL2iDhPja17Z0PoIh2cZNmNh13dDvzSoRnRuzsZCsqSjVLWp
8tWA4PSsvs9Z0fww2rU31It+Rg10s7BvE4b6onyiPCCcHnx4scp6fV45bEhN3vDi
MK8GaT80kC09Fd1GZgObVKk/qo/FCsOIvLInKgOMZ6SyqfM0Jh0dYD7AORSrNQEm
keHhCwJwGbOUpsgjYXLt4TZv2HnMfuAh91SbPci56bRBsH0MaqkuF5HMuIKmSN9K
ryJUnhIYg7vSjd6jeALOYyvBNg5vwlXdyo56Nc/khRC0eIhb3mAOxHeQlwLwezoH
HmZRvXaY9vd3i9q8m2564tVq4Botb1hfG+uQ7e58rrQ=
-----END RSA PRIVATE KEY-----
`
var testKey_AES_128_OFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-OFB,A9BB7756F20E18D37B48CA1A358C3CDA

oOKtTBFX4QMStx8Bn3494nEcNy9FWomn5JZKgWOeiFir91ibRDeMtO7B1aj1hohO
p8Xw7FvYN//oazGk1AG5W6FIUiBsV7zA72ykw8eq4su4GaatScxbpjIk2zCVUMXX
M2/giO+YFV8dk566GYDRBjRdSk1gwDp83Bi+lqdY/a5W1FEoDXKxFJBzvtzc6kpi
y6uBYHxBAkuWlj0kx6gzpHrhyE9thD7vOcbSTtT6Sslns6f4NDx/RrDHIGTIRYLz
yOUy9Ci4d86PeyQ5WHkCuXAoe0aLX6OjrnGJw2c//Vy1fcP6AYce+6AaNJ2/BQjr
EbywWmcOi3389fc5uCrcKQSzSc+Y8Q1IWSutlpJfz0H8ZBttf25UKUEWZGwBjTtH
7pHS7AAiTOwGo1R7bB0PwGP658FZLJwy4zf08KdtguDHGFXgWYZ4f6wCgn+S6+4d
nlrjPWkZV1GoZjZEc5Fw1MBFvQ+e1a98FjgV1dRSSGlbyZ55N+bd/drsoGZJUgeI
aMlr45okne94c6CnYc1PkFCA3mKSOGx3sRVtzgKDyb9lr3t3m+9iCnmTJVfNfy8F
RB/yNPpotccMUqoWJlMhvF8pDRU4iXd7y8J+s9ktcSYOJ3NQS7cAPOV8XVcvfbtr
dg+HDc7Bsj4BquslwxaChxvNLfEFJxqixot41MjrpQZS52Nv7P0pWWGD85rRAsxx
blXNVyALUPAUM59RzLmk1tmn3ucxEFe+n/1ss13HbXygonqAnk73fFE4TqjsjKow
/QQx1/NHpsKEGfTaEXgQPpTTaGoYmiVgcLkTeWNLrZA=
-----END RSA PRIVATE KEY-----
`
var testKey_AES_128_CFB = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CFB,35F0FFB8D97ECD6D69F73B28D98A6BB7

3wf0Vj9bz568z2J0iTKdr56qoAe5NgDaN3EdMPnPQ16xAwlztbE9VPtx2zmQ/RK9
h/JZJbtWZel8SbvO9xRAuJXe/20YVvZ2zsJo3FBymjsgTF79PpQj/iixpmajNVBM
nrkNDSJ/B/4cAkDx3/4pGupy3g104uh8JZFjZCHxCwhiU/ATw67JWWpt5k9DzwHX
BuYdzzGwzSkTCTEqXDxedGfns+Wo177EcyBWlWWqAieHTfXepUgOyz9JS1JU0GSv
RhhjGDocOciQMBLSqho+hFJYzu6fB/TU0v04Q+yhHWt7PeSWOpWmG9ObuL2iMVpo
REPRLTkiwwTXhWmd4xODJ3yae2moRwk2hWtSK4TZgsIHY75JmLZTpqB1INMgVA5j
CWHCZv4CU6yeLtcJBBsDm11uk2Av7PInDoopQWpmtnWs7QiCQZeL0EPFYcx/qz0q
QIF82iHFgSeSXJ0hSsjTNzzjLvAw9/3VABcd0PaSiJN7qjNAH1Opi32EVmuGlV5j
CofMEja94bDowTEEDDR8kKnSCd5CsiglSLlWZ014XgSpGZylE4B/R43PFvKSradD
VjEia0sJl1AfIxa3upWkd8nequoddeOVU+Xklzkr0VpIBHomSEdOdyvHatTPPWzx
II9th5ifLh5kqgKx4ruR9pSsoX5A+6WnUecvF+x0T7Qt2D9NA1qaVju8Fpw+YEJQ
fbavDLrIGxjTi+Hebc14oXK2qsKli+pV3r9We94GWNPj035aT0sDdx+5IxLH6ule
rXQarl3KI5nheAON9KJI+f0U4S7vYfC3oFgwdpyVee4=
-----END RSA PRIVATE KEY-----
`


func Test_Check_PEMBlock(t *testing.T) {
    t.Run("DES_CTR", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_DES_CTR)
    })
    t.Run("DES_OFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_DES_OFB)
    })
    t.Run("DES_CFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_DES_CFB)
    })

    t.Run("3DES_CFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_3DES_CFB)
    })
    t.Run("3DES_OFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_3DES_OFB)
    })
    t.Run("3DES_CTR", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_3DES_CTR)
    })

    t.Run("AES_256_CTR", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_256_CTR)
    })
    t.Run("AES_256_OFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_256_OFB)
    })
    t.Run("AES_256_CFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_256_CFB)
    })

    t.Run("AES_192_CTR", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_192_CTR)
    })
    t.Run("AES_192_OFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_192_OFB)
    })
    t.Run("AES_192_CFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_192_CFB)
    })

    t.Run("AES_128_CTR", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_128_CTR)
    })
    t.Run("AES_128_OFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_128_OFB)
    })
    t.Run("AES_128_CFB", func(t *testing.T) {
        testKeyEncryptPEMBlock(t, testKey_AES_128_CFB)
    })
}

var testKeyOldKey = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CFB,FEE6BA57503D765BC6D87BC6954A0D72

bq7Nbbr5BF8Me+OXceRQQAc/S3wcD6Q9XLQgHZpwulLkw780ooTU5C51d/4JmPcM
NZDo35EPjCG4jb2wEvdWItpn7nF3LMnTOvJfcpH03NbgNfbLgn+jvckkU1ehOPoi
UHgww/4jjEGeKRTefzbjxEg4rD2aRuxe34yR8GlCOR39UxdziIQytxPvRl/Ad184
+QeqFb6cW2MgMUPkAL/PA4H1TfSg6xCET5ewMhgHTTaE9sEmDYtlxCVEkhLTr21O
avMHvLgQS+iQrE4h3iJ9jvWWsUUYTIfCpNrN0dujClX/RPETfiNhUihHXasA//qh
+0wBh3zroF/+2TEYXwPOJyHBKULEgUBxm8mdSlHLf93mkMpYs6josC3XthpPzX46
P2nC2Pt7lzs5MRNIMlj4DWCODOzuDphUJ88Gt+g5SCOl05fqRka5Qy5vSWc3v6/3
UJI9yj+eNFF7d0TjW3saMF4m7x206q90LL2d3gN4hNA2a+yVTiUQ6/HIlAebffTh
RWptkznl0BSJkvUu+jon16KnPYQvuyFiI6KN1GUKL3a58OmfNljmNYyY9dOjjT0D
IrHJbDgyuwLcQ2WhafdTDWt5Zj2U1vh2GbkNAxQzljbDku3l5wvaJvSQSHK+k2uI
0pHc3RENOFZ751b7A+H23Y7V/Kqi9tWfCqFo0Ybdc8kah1a1+zyxSrq7FEhUG8ja
EJI6g3hykcWb6Xv6g4qCNxt93nTyPIxeJsOhCiValjJGT5DxzCGjcwWKh0xCTAOF
UR9uChIsW6/OIOevnvffncQoPNOLZx8XorAdD8ABtg==
-----END RSA PRIVATE KEY-----
`

func TestEncryptPEMBlock(t *testing.T) {
    block, _ := pem.Decode([]byte(testKeyOldKey))

    bys, err := DecryptPEMBlock(block, []byte("123"))
    if err != nil {
        t.Fatal("PEM data decrypted error: " + err.Error())
    }

    enblock, err := EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", bys, []byte("123"), Cipher3DESCBC)
    if err != nil {
        t.Error("encrypt: ", err)
    }

    if len(enblock.Bytes) == 0 {
        t.Error("EncryptPEMBlock error")
    }

    if false {
        newkeyData := pem.EncodeToMemory(enblock)
        t.Error("encrypt data: \r\n", string(newkeyData))
    }
}
