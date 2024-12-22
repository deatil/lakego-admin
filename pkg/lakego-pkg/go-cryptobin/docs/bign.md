### Bign 使用文档

#### 包引入
~~~go
import (
    "github.com/deatil/go-cryptobin/cryptobin/bign"
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
    // 可选 [Bign256v1 | Bign384v1 | Bign512v1]
    gen := bign.GenerateKey("Bign256v1")

    // 生成私钥 PEM 证书
    privateKeyPEM := gen.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword(password, "AES256CBC").
        // CreatePKCS1PrivateKey()
        // CreatePKCS1PrivateKeyWithPassword(password, "AES256CBC")
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword(password, "AES256CBC", "SHA256").
        ToKeyString()

    // 生成公钥 PEM 证书
    publicKeyPEM := gen.
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

    // 私钥签名
    var prikeyPem []byte = []byte("...")
    var base64signedString string = bign.
        FromString("test-pass").
        FromPrivateKey(prikeyPem).
        // FromPrivateKeyWithPassword(prikeyPem, password).
        // FromPKCS1PrivateKey(prikeyPem).
        // FromPKCS1PrivateKeyWithPassword(prikeyPem, password).
        // FromPKCS8PrivateKey(prikeyPem).
        // FromPKCS8PrivateKeyWithPassword(prikeyPem, password).
        // WithEncodingASN1().
        // WithEncodingBytes().
        WithAdata(adata). // 设置 adata 参数
        Sign().
        ToBase64String()

    // 公钥验证
    var pubkeyPem []byte = []byte("...")
    var base64signedString string = "..."
    var verify bool = bign.
        FromBase64String(base64signedString).
        FromPublicKey(pubkeyPem).
        // WithEncodingASN1().
        // WithEncodingBytes().
        WithAdata(adata). // 设置 adata 参数
        Verify([]byte("test-pass")).
        ToVerify()
}
~~~


#### 检测私钥公钥是否匹配
~~~go
func main() {
    var prikeyPem []byte = []byte("...")
    var pubkeyPem []byte = []byte("...")

    // 私钥密码
    // privatekey password
    var password string = ""

    var res bool = bign.New().
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
