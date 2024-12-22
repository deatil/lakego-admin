### Rsa 使用文档 / RSA Docs

`EncryptECB`, `PrivateKeyEncryptECB`, `EncryptOAEPECB` 为 `JAVA` 对应的 `ECB` 模式，可加密大数据
`EncryptECB`, `PrivateKeyEncryptECB`, `EncryptOAEPECB`  for `JAVA` `ECB` mode and can encrypt big data


#### 包引入 / import pkg
~~~go
import (
    "github.com/deatil/go-cryptobin/cryptobin/rsa"
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

#### 生成证书 / make keys
~~~go
func main() {
    // 私钥密码
    // privatekey password
    var password string = ""

    // bits = 512 | 1024 | 2048 | 4096
    obj := rsa.New().
        GenerateKey(2048)
        // GenerateMultiPrimeKey(nprimes int, bits int)

    // 生成私钥
    // create private key
    var PriKeyPem string = obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword(password, "AES256CBC").
        // CreatePKCS1PrivateKey().
        // CreatePKCS1PrivateKeyWithPassword(password, "AES256CBC").
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword(password, "AES256CBC", "SHA256").
        // CreateXMLPrivateKey().
        ToKeyString()

    // 自定义私钥加密类型
    // use custom encrypt options
    var PriKeyPem string = obj.
        CreatePKCS8PrivateKeyWithPassword(password, rsa.Opts{
            Cipher:  rsa.GetCipherFromName("AES256CBC"),
            KDFOpts: rsa.ScryptOpts{
                CostParameter:            1 << 15,
                BlockSize:                8,
                ParallelizationParameter: 1,
                SaltSize:                 8,
            },
        }).
        ToKeyString()

    // 生成公钥
    // create public key
    var PubKeyPem string = obj.
        CreatePKCS1PublicKey().
        // CreatePKCS8PublicKey().
        // CreateXMLPublicKey().
        ToKeyString()
}
~~~

#### 签名验证 / sign data
~~~go
func main() {
    obj := rsa.New()

    // 待签名数据
    // no sign data
    var data string = "..."

    // 签名数据
    // sign data
    var sigBase64String string = "..."

    // 私钥密码
    // privatekey password
    var password string = ""

    // 私钥签名
    // private key sign data
    var priKeyPem []byte = []byte("...")
    var priKeyXML []byte = []byte("...")
    sigBase64String = obj.
        FromString(data).
        FromPrivateKey(priKeyPem).
        // FromPrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS1PrivateKey(priKeyPem).
        // FromPKCS1PrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS8PrivateKey(priKeyPem).
        // FromPKCS8PrivateKeyWithPassword(priKeyPem, password).
        // FromXMLPrivateKey(priKeyXML).
        SetSignHash("SHA256").
        Sign().
        // SignPSS().
        ToBase64String()

    // 公钥验证
    // public key verify signed data
    var pubKeyPem []byte = []byte("...")
    var pubKeyXML []byte = []byte("...")
    var res bool = obj.
        FromBase64String(sigBase64String).
        FromPublicKey(pubKeyPem).
        // FromPKCS1PublicKey(pubKeyPem).
        // FromPKCS8PublicKey(pubKeyPem).
        // FromXMLPublicKey(pubKeyXML).
        SetSignHash("SHA256").
        Verify([]byte(data)).
        // VerifyPSS([]byte(data)).
        ToVerify()
}
~~~

#### 加密解密 - 公钥加密/私钥解密 / Encrypt with public key
~~~go
func main() {
    obj := rsa.New()

    // 待加密数据
    // no sign data
    var data string = "..."

    // 私钥密码
    // privatekey password
    var password string = ""

    // 公钥加密
    // public key Encrypt data
    var pubKeyPem []byte = []byte("...")
    var pubKeyXML []byte = []byte("...")
    var enData string = obj.
        FromString(data).
        FromPublicKey(pubKeyPem).
        // FromPKCS1PublicKey(pubKeyPem).
        // FromPKCS8PublicKey(pubKeyPem).
        // FromXMLPublicKey(pubKeyXML).
        Encrypt().
        // SetOAEPHash("SHA256"). // OAEP 可选
        // SetOAEPLabel("test-label"). // OAEP 可选
        // EncryptOAEP()
        ToBase64String()

    // 私钥解密
    // private key Decrypt data
    var priKeyPem []byte = []byte("...")
    var priKeyXML []byte = []byte("...")
    var deData string = obj.
        FromBase64String(enData).
        FromPrivateKey(priKeyPem).
        // FromPrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS1PrivateKey(priKeyPem).
        // FromPKCS1PrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS8PrivateKey(priKeyPem).
        // FromPKCS8PrivateKeyWithPassword(priKeyPem, password).
        // FromXMLPrivateKey(priKeyXML).
        Decrypt().
        // SetOAEPHash("SHA256"). // OAEP 可选
        // SetOAEPLabel("test-label"). // OAEP 可选
        // DecryptOAEP()
        ToString()
}
~~~

#### 加密解密 - 私钥加密/公钥解密 / Encrypt with private key
~~~go
func main() {
    obj := rsa.New()

    // 待加密数据
    // no sign data
    var data string = "..."

    // 私钥密码
    // privatekey password
    var password string = ""

    // 私钥加密
    // private key Decrypt data
    var priKeyPem []byte = []byte("...")
    var priKeyXML []byte = []byte("...")
    var enData string = obj.
        FromString(data).
        FromPrivateKey(priKeyPem).
        // FromPrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS1PrivateKey(priKeyPem).
        // FromPKCS1PrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS8PrivateKey(priKeyPem).
        // FromPKCS8PrivateKeyWithPassword(priKeyPem, password).
        // FromXMLPrivateKey(priKeyXML).
        PrivateKeyEncrypt().
        ToBase64String()

    // 公钥解密
    // public key Encrypt data
    var pubKeyPem []byte = []byte("...")
    var pubKeyXML []byte = []byte("...")
    var deData string = obj.
        FromBase64String(enData).
        FromPublicKey(pubKeyPem).
        // FromPKCS1PublicKey(pubKeyPem).
        // FromPKCS8PublicKey(pubKeyPem).
        // FromXMLPublicKey(pubKeyXML).
        PublicKeyDecrypt().
        ToString()
}
~~~

#### 检测私钥公钥是否匹配 / Check KeyPair
~~~go
func main() {
    var prikeyPem []byte = []byte("...")
    var pubkeyPem []byte = []byte("...")

    var priKeyXML []byte = []byte("...")
    var pubKeyXML []byte = []byte("...")

    // 私钥密码
    // privatekey password
    var password string = ""

    var res bool = rsa.New().
        // FromPrivateKey(prikeyPem).
        // FromPrivateKeyWithPassword(prikeyPem, password).
        // FromPKCS1PrivateKey(prikeyPem).
        // FromPKCS1PrivateKeyWithPassword(prikeyPem, password).
        FromPKCS8PrivateKey(prikeyPem).
        // FromPKCS8PrivateKeyWithPassword(prikeyPem, password).
        // FromXMLPrivateKey(priKeyXML).
        // FromPublicKey(pubkeyPem).
        // FromPKCS1PublicKey(pubkeyPem).
        FromPKCS8PublicKey(pubkeyPem).
        // FromXMLPublicKey(pubKeyXML).
        CheckKeyPair()
}
~~~

#### 私钥公钥证书解析 / Parse PrivateKey or PublicKey
~~~go
import (
    go_rsa "crypto/rsa"
)

func main() {
    // 私钥解析
    // Parse PrivateKey
    var priKeyPem []byte = []byte("")
    var priKeyXML []byte = []byte("")

    // 私钥密码
    // privatekey password
    var password string = ""

    var parsedPrivateKey *go_rsa.PrivateKey = rsa.New().
        FromPrivateKey(priKeyPem).
        // FromPrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS1PrivateKey(priKeyPem).
        // FromPKCS1PrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS8PrivateKey(priKeyPem).
        // FromPKCS8PrivateKeyWithPassword(priKeyPem, password).
        // FromXMLPrivateKey(priKeyXML).
        GetPrivateKey()

    // 公钥解析
    // Parse PublicKey
    var pubKeyPem []byte = []byte("")
    var pubKeyXML []byte = []byte("")

    var parsedPublicKey *go_rsa.PublicKey = rsa.New().
        FromPublicKey(pubKeyPem).
        // FromPKCS1PublicKey(pubKeyPem).
        // FromPKCS8PublicKey(pubKeyPem).
        // FromXMLPublicKey(pubKeyXML).
        GetPublicKey()
}
~~~

#### 私钥公钥证书编码格式转换 / Change PrivateKey or PublicKey type
~~~go
func main() {
    // 私钥编码转换
    // PrivateKey change type
    var priKeyPem []byte = []byte("")
    var priKeyXML []byte = []byte("")

    // 私钥密码
    // privatekey password
    var password string = ""

    var newPrivateKey string = rsa.New().
        // FromPrivateKey(priKeyPem).
        // FromPrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS1PrivateKey(priKeyPem).
        FromPKCS1PrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS8PrivateKey(priKeyPem).
        // FromPKCS8PrivateKeyWithPassword(priKeyPem, password).
        // FromXMLPrivateKey(priKeyXML).
        // CreatePrivateKey().
        // CreatePrivateKeyWithPassword(password, "AES256CBC").
        // CreatePKCS1PrivateKey().
        // CreatePKCS1PrivateKeyWithPassword(password, "AES256CBC").
        CreatePKCS8PrivateKey(). // 转为 PKCS8 编码
        // CreatePKCS8PrivateKeyWithPassword(password, "AES256CBC", "SHA256").
        // CreateXMLPrivateKey().
        ToKeyString()

    // 公钥编码转换
    // PublicKey change type
    var pubKeyPem []byte = []byte("")
    var pubKeyXML []byte = []byte("")

    var newPublicKey string = rsa.New().
        FromPublicKey(pubKeyPem).
        // FromPKCS1PublicKey(pubKeyPem).
        // FromPKCS8PublicKey(pubKeyPem).
        // FromXMLPublicKey(pubKeyXML).
        // CreatePKCS1PublicKey().
        CreatePKCS8PublicKey(). // 转为 PKCS8 编码
        // CreateXMLPublicKey().
        ToKeyString()
}
~~~
