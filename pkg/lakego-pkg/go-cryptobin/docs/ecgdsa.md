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
    var psssword string = ""

    // 生成证书
    // 可选参数 [P521 | P384 | P256 | P224]
    ec := ecgdsa.GenerateKey("P521")

    // 生成私钥 PEM 证书
    privateKeyString := ec.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword(psssword, "AES256CBC").
        // CreatePKCS1PrivateKey()
        // CreatePKCS1PrivateKeyWithPassword(password string, opts ...string)
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword(psssword, "AES256CBC", "SHA256").
        ToKeyString()

    // 生成公钥 PEM 证书
    publicKeyString := ec.
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

字节拼接:
SignBytes() / VerifyBytes(data []byte)
~~~

示例
~~~go
func main() {
    // 私钥密码
    // privatekey password
    var psssword string = ""

    // 私钥签名
    var pri []byte = []byte("...")
    var base64signedString string = ecgdsa.
        FromString("test-pass").
        FromPrivateKey(pri).
        // FromPrivateKeyWithPassword(pri, psssword).
        // FromPKCS1PrivateKey(pri).
        // FromPKCS1PrivateKeyWithPassword(pri, psssword).
        // FromPKCS8PrivateKey(pri).
        // FromPKCS8PrivateKeyWithPassword(pri, psssword).
        Sign().
        ToBase64String()

    // 公钥验证
    var pub []byte = []byte("...")
    var base64signedString string = "..."
    var verify bool = ecgdsa.
        FromBase64String(base64signedString).
        FromPublicKey(pub).
        Verify([]byte("test-pass")).
        ToVerify()
}
~~~


#### 检测私钥公钥是否匹配
~~~go
func main() {
    // 私钥密码
    // privatekey password
    var psssword string = ""

    var prikeyPem []byte = []byte("...")
    var pubkeyPem []byte = []byte("...")

    var res bool = ecgdsa.New().
        FromPrivateKey(pri).
        // FromPrivateKeyWithPassword(pri, psssword).
        // FromPKCS1PrivateKey(pri).
        // FromPKCS1PrivateKeyWithPassword(pri, psssword).
        // FromPKCS8PrivateKey(pri).
        // FromPKCS8PrivateKeyWithPassword(pri, psssword).
        FromPublicKey(pubkey).
        CheckKeyPair()
}
~~~
