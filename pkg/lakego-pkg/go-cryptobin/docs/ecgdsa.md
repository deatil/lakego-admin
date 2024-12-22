### EC-GDSA 使用文档

#### 包引入
~~~go
import (
    "github.com/deatil/go-cryptobin/cryptobin/ecgdsa"
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
    ec := ecgdsa.GenerateKey("P521")

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
    var base64signedString string = ecgdsa.
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
    var pubPEM []byte = []byte("...")
    var base64signedString string = "..."
    var verify bool = ecgdsa.
        FromBase64String(base64signedString).
        FromPublicKey(pubPEM).
        Verify([]byte(data)).
        ToVerify()
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

    var res bool = ecgdsa.New().
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
