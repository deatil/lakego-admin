### EcDsa 使用说明

* 包引入
~~~go
import (
    "github.com/deatil/go-cryptobin/cryptobin/ecdsa"
)
~~~

* 数据输入方式
`FromBytes(data []byte)`, `FromString(data string)`, `FromBase64String(data string)`, `FromHexString(data string)`

* 数据输出方式
`ToBytes()`, `ToString()`, `ToBase64String()`, `ToHexString()`, 

* 生成证书
~~~go
func main() {
    // 生成证书
    // 可选参数 [P521 | P384 | P256 | P224]
    ec := ecdsa.GenerateKey("P521")

    // 生成私钥 PEM 证书
    privateKeyString := ec.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        // CreatePKCS1PrivateKey()
        // CreatePKCS1PrivateKeyWithPassword(password string, opts ...string)
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256").
        ToKeyString()

    // 生成公钥 PEM 证书
    publicKeyString := ec.
        CreatePublicKey().
        ToKeyString()
}
~~~

* 签名验证

签名验证支持以下方式
~~~
sep符号分割: Sign(separator ...string) / Verify(data []byte, separator ...string)
ASN1方式: SignASN1() / VerifyASN1(data []byte)
字节组合: SignBytes() / VerifyBytes(data []byte)
~~~

示例
~~~go
func main() {
    // 私钥签名
    var pri []byte = []byte("...")
    var base64signedString string = ecdsa.
        FromString("test-pass").
        FromPrivateKey(pri).
        // FromPrivateKeyWithPassword(pri, "123").
        // FromPKCS1PrivateKey(pri).
        // FromPKCS1PrivateKeyWithPassword(pri, "123").
        // FromPKCS8PrivateKey(pri).
        // FromPKCS8PrivateKeyWithPassword(pri, "123").
        Sign().
        ToBase64String()
    
    // 公钥验证
    var pub []byte = []byte("...")
    var base64signedString string = "..."
    var verify bool = ecdsa.
        FromBase64String(base64signedString).
        FromPublicKey(pub).
        Verify([]byte("test-pass")).
        ToVerify()
}
~~~

* 加密解密

ECDSA 加密使用自身的 ECDH 生成密钥，使用 AES 对称加密解密数据

~~~go
func main() {
    // 私钥
    prikey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGfqpFWW2kecvy/V0mxus+ZMuODGcqfyZVJMgBbWRhYJoAoGCCqGSM49
AwEHoUQDQgAEqktVUz5Og3mBcnhpnfWWSOhrZqO+Vu0zCh5hkl/0r9vPzPeqGpHJ
v3eJw/zF+gZWxn2LvLcKkQTcGutSwVdVRQ==
-----END EC PRIVATE KEY-----
    `

    // 公钥
    pubkey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqktVUz5Og3mBcnhpnfWWSOhrZqO+
Vu0zCh5hkl/0r9vPzPeqGpHJv3eJw/zF+gZWxn2LvLcKkQTcGutSwVdVRQ==
-----END PUBLIC KEY-----
    `

    // 加密
    var encBase64Data string = ecdsa.
        FromString("test-pass").
        FromPublicKey([]byte(pubkey)).
        Encrypt().
        ToBase64String()

    // 解密
    var encBase64Data string = ""
    var deData string = ecdsa.
        FromBase64String(encBase64Data).
        FromPrivateKey([]byte(prikey)).
        Decrypt().
        ToString()
}
~~~

* 检测私钥公钥是否匹配
~~~go
func main() {
    var prikeyPem []byte = []byte("...")
    var pubkeyPem []byte = []byte("...")

    var res bool = ecdsa.New().
        FromPrivateKey(prikey).
        FromPublicKey(pubkey).
        CheckKeyPair()
}
~~~
