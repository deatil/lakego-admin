### DSA 使用文档

#### 包引入 / import pkg
~~~go
import (
    "github.com/deatil/go-cryptobin/cryptobin/dsa"
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
    // 可用参数 [L1024N160 | L2048N224 | L2048N256 | L3072N256]
    obj := dsa.New().GenerateKey("L2048N256")

    // 生成私钥
    // create private key
    var PriKeyPem string = obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        // CreatePKCS1PrivateKey().
        // CreatePKCS1PrivateKeyWithPassword("123", "AES256CBC").
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256").
        // CreateXMLPrivateKey().
        ToKeyString()

    // 自定义私钥加密类型
    // use custom encrypt options
    var PriKeyPem string = obj.
        CreatePKCS8PrivateKeyWithPassword("123", rsa.Opts{
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
    obj := dsa.New()

    // 待签名数据
    // no sign data
    var data string = "..."

    // 签名数据
    // sign data
    var sigBase64String string = "..."

    // 私钥签名
    // private key sign data
    var priKeyPem string = ""
    sigBase64String = obj.
        FromString(data).
        FromPrivateKey([]byte(priKeyPem)).
        // FromPrivateKeyWithPassword([]byte(priKeyPem), "123").
        // FromPKCS1PrivateKey([]byte(priKeyPem)).
        // FromPKCS1PrivateKeyWithPassword([]byte(priKeyPem), "123").
        // FromPKCS8PrivateKey([]byte(priKeyPem)).
        // FromPKCS8PrivateKeyWithPassword([]byte(priKeyPem), "123").
        // FromXMLPrivateKey([]byte(priKeyXML)).
        SetSignHash("SHA256").
        Sign().
        // SignASN1().
        // SignBytes().
        // SignWithSeparator().
        ToBase64String()

    // 公钥验证
    // public key verify signed data
    var pubKeyPem string = ""
    var res bool = obj.
        FromBase64String(sigBase64String).
        FromPublicKey([]byte(pubKeyPem)).
        // FromPKCS1PublicKey([]byte(pubKeyPem)).
        // FromPKCS8PublicKey([]byte(pubKeyPem)).
        // FromXMLPublicKey([]byte(pubKeyXML)).
        SetSignHash("SHA256").
        Verify([]byte(data)).
        // VerifyASN1([]byte(data)).
        // VerifyBytes([]byte(data)).
        // VerifyWithSeparator([]byte(data)).
        ToVerify()
}
~~~

#### 检测私钥公钥是否匹配 / Check KeyPair
~~~go
func main() {
    var prikeyPem string = "..."
    var pubkeyPem string = "..."

    var res bool = dsa.New().
        // FromPrivateKey([]byte(prikeyPem)).
        // FromPrivateKeyWithPassword([]byte(prikeyPem), "123").
        // FromPKCS1PrivateKey([]byte(prikeyPem)).
        // FromPKCS1PrivateKeyWithPassword([]byte(prikeyPem), "123").
        FromPKCS8PrivateKey([]byte(prikeyPem)).
        // FromPKCS8PrivateKeyWithPassword([]byte(prikeyPem), "123").
        // FromPublicKey([]byte(pubkeyPem)).
        // FromPKCS1PublicKey([]byte(pubkeyPem)).
        FromPKCS8PublicKey([]byte(pubkeyPem)).
        CheckKeyPair()
}
~~~
