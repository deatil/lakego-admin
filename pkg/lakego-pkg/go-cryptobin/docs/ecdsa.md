### ECDSA 使用文档

#### 包引入
~~~go
import (
    "github.com/deatil/go-cryptobin/cryptobin/ecdsa"
)
~~~

#### 数据输入方式 / input funcs
~~~go
FromBytes(data []byte)
FromString(data string)
FromBase64String(data string)
FromHexString(data string)
~~~

#### 数据输出方式 / output funcs
~~~go
ToBytes()
ToString()
ToBase64String()
ToHexString()
~~~

#### 获取 error / get error
~~~go
Error()
~~~

#### 生成证书
~~~go
func main() {
    // 私钥密码
    // privatekey password
    var password string = ""

    // 生成证书
    // 可选参数 [P521 | P384 | P256 | P224]
    ec := ecdsa.GenerateKey("P521")

    // 生成私钥 PEM 证书
    privateKeyPEM := ec.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword(password, "AES256CBC").
        // CreatePKCS1PrivateKey()
        // CreatePKCS1PrivateKeyWithPassword(password, "AES256CBC")
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword(password, "AES256CBC", "SHA256").
        ToKeyString()

    // 生成公钥 PEM 证书
    publicKeyPEM := ec.
        CreatePublicKey().
        ToKeyString()
}
~~~

#### 签名验证

签名验证支持以下方式
~~~
默认方法:
Sign() / Verify(data []byte)

ASN1编码，为默认方法别名:
SignASN1() / VerifyASN1(data []byte)

明文字节拼接:
SignBytes() / VerifyBytes(data []byte)
~~~

示例
~~~go
func main() {
    // 私钥密码
    // privatekey password
    var password string = ""

    var data string = "test-pass"

    // 私钥签名
    var priPEM []byte = []byte("...")
    var base64signedString string = ecdsa.
        FromString(data).
        FromPrivateKey(priPEM).
        // FromPrivateKeyWithPassword(priPEM, password).
        // FromPKCS1PrivateKey(priPEM).
        // FromPKCS1PrivateKeyWithPassword(priPEM, password).
        // FromPKCS8PrivateKey(priPEM).
        // FromPKCS8PrivateKeyWithPassword(priPEM, password).
        Sign().
        ToBase64String()

    // 公钥验证
    var pubEM []byte = []byte("...")
    var base64signedString string = "..."
    var verify bool = ecdsa.
        FromBase64String(base64signedString).
        FromPublicKey(pubEM).
        Verify([]byte(data)).
        ToVerify()
}
~~~

#### 加密解密

ECDSA 加密使用自身的 ECDH 生成的密钥，使用 AES 对称加密解密数据

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

#### 检测私钥公钥是否匹配
~~~go
func main() {
    // 私钥密码
    // privatekey password
    var password string = ""

    var prikeyPem []byte = []byte("...")
    var pubkeyPem []byte = []byte("...")

    var res bool = ecdsa.New().
        FromPrivateKey(prikeyPem).
        // FromPrivateKeyWithPassword(prikeyPem, password).
        // FromPKCS1PrivateKey(prikeyPem).
        // FromPKCS1PrivateKeyWithPassword(prikeyPem, password).
        // FromPKCS8PrivateKey(prikeyPem).
        // FromPKCS8PrivateKeyWithPassword(prikeyPem, password).
        FromPublicKey(pubkeyPem).
        CheckKeyPair()
}
~~~
