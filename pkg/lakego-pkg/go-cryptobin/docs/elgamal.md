### ElGamal 使用文档

#### 包引入 / import pkg
~~~go
import (
    "github.com/deatil/go-cryptobin/cryptobin/elgamal"
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
    obj := elgamal.New().GenerateKey(256, 64)

    // 私钥密码
    // privatekey password
    var psssword string = ""

    // 生成私钥
    // create private key
    var PriKeyPem string = obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword(psssword, "DESEDE3CBC").
        // CreatePKCS1PrivateKey().
        // CreatePKCS1PrivateKeyWithPassword(psssword, "DESEDE3CBC").
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword(psssword, "AES256CBC").
        ToKeyString()

    // 自定义私钥加密类型
    // use custom encrypt options
    var PriKeyPem string = obj.
        CreatePKCS8PrivateKeyWithPassword(psssword, sm2.Opts{
            Cipher:  sm2.GetCipherFromName("AES256CBC"),
            KDFOpts: sm2.ScryptOpts{
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
        CreatePublicKey().
        // CreatePKCS1PublicKey().
        // CreatePKCS8PublicKey().
        ToKeyString()
}
~~~

#### 签名验证 / sign data
~~~go
func main() {
    // 待签名数据
    // no sign data
    var data string = "..."

    // 签名数据
    // sign data
    var sigBase64String string = "..."

    // 私钥密码
    // privatekey password
    var psssword string = ""

    obj := elgamal.New()

    // 私钥签名
    // private key sign data
    var priKeyPem string = ""
    sigBase64String = obj.
        FromString(data).
        FromPrivateKey([]byte(priKeyPem)).
        // FromPrivateKeyWithPassword([]byte(priKeyPem), psssword).
        // FromPKCS1PrivateKey([]byte(priKeyPem)).
        // FromPKCS1PrivateKeyWithPassword([]byte(priKeyPem), psssword).
        // FromPKCS8PrivateKey([]byte(priKeyPem)).
        // FromPKCS8PrivateKeyWithPassword([]byte(priKeyPem), psssword).
        Sign().
        ToBase64String()

    // 公钥验证
    // public key verify signed data
    var pubKeyPem string = ""
    var res bool = obj.
        FromBase64String(sigBase64String).
        FromPublicKey([]byte(pubKeyPem)).
        // FromPKCS1PublicKey([]byte(pubKeyPem)).
        // FromPKCS8PublicKey([]byte(pubKeyPem)).
        Verify([]byte(data)).
        ToVerify()
}
~~~

#### 加密解密 - 公钥加密/私钥解密 / Encrypt with public key
~~~go
func main() {
    obj := elgamal.New()

    // 待加密数据
    // no sign data
    var data string = "..."

    // 私钥密码
    // privatekey password
    var psssword string = ""

    // 公钥加密
    // public key Encrypt data
    var pubKeyPem string = ""
    var enData string = obj.
        FromString(data).
        FromPublicKey([]byte(pubKeyPem)).
        // FromPKCS1PublicKey([]byte(pubKeyPem)).
        // FromPKCS8PublicKey([]byte(pubKeyPem)).
        Encrypt().
        ToBase64String()

    // 私钥解密
    // private key Decrypt data
    var priKeyPem string = ""
    var deData string = obj.
        FromBase64String(enData).
        FromPrivateKey([]byte(priKeyPem)).
        // FromPrivateKeyWithPassword([]byte(priKeyPem), psssword).
        // FromPKCS1PrivateKey([]byte(priKeyPem)).
        // FromPKCS1PrivateKeyWithPassword([]byte(priKeyPem), psssword).
        // FromPKCS8PrivateKey([]byte(priKeyPem)).
        // FromPKCS8PrivateKeyWithPassword([]byte(priKeyPem), psssword).
        Decrypt().
        ToString()
}
~~~

#### 检测私钥公钥是否匹配 / Check KeyPair
~~~go
func main() {
    var prikeyPem string = "..."
    var pubkeyPem string = "..."

    // 私钥密码
    // privatekey password
    var psssword string = ""

    var res bool = elgamal.New().
        // FromPrivateKey([]byte(prikeyPem)).
        // FromPrivateKeyWithPassword([]byte(prikeyPem), psssword).
        // FromPKCS1PrivateKey([]byte(prikeyPem)).
        // FromPKCS1PrivateKeyWithPassword([]byte(prikeyPem), psssword).
        FromPKCS8PrivateKey([]byte(prikeyPem)).
        // FromPKCS8PrivateKeyWithPassword([]byte(prikeyPem), psssword).
        // FromPublicKey([]byte(pubkeyPem)).
        // FromPKCS1PublicKey([]byte(pubkeyPem)).
        FromPKCS8PublicKey([]byte(pubkeyPem)).
        CheckKeyPair()
}
~~~
