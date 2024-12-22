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
    var password string = ""

    // 生成私钥
    // create private key
    var PriKeyPem string = obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword(password, "AES256CBC").
        // CreatePKCS1PrivateKey().
        // CreatePKCS1PrivateKeyWithPassword(password, "AES256CBC").
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword(password, "AES256CBC").
        ToKeyString()

    // 自定义私钥加密类型
    // use custom encrypt options
    var PriKeyPem string = obj.
        CreatePKCS8PrivateKeyWithPassword(password, sm2.Opts{
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
    var password string = ""

    obj := elgamal.New()

    // 私钥签名
    // private key sign data
    var priKeyPem []byte = []byte("...")
    sigBase64String = obj.
        FromString(data).
        FromPrivateKey(priKeyPem).
        // FromPrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS1PrivateKey(priKeyPem).
        // FromPKCS1PrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS8PrivateKey(priKeyPem).
        // FromPKCS8PrivateKeyWithPassword(priKeyPem, password).
        Sign().
        ToBase64String()

    // 公钥验证
    // public key verify signed data
    var pubKeyPem []byte = []byte("...")
    var res bool = obj.
        FromBase64String(sigBase64String).
        FromPublicKey(pubKeyPem).
        // FromPKCS1PublicKey(pubKeyPem).
        // FromPKCS8PublicKey(pubKeyPem).
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
    var password string = ""

    // 公钥加密
    // public key Encrypt data
    var pubKeyPem []byte = []byte("...")
    var enData string = obj.
        FromString(data).
        FromPublicKey(pubKeyPem).
        // FromPKCS1PublicKey(pubKeyPem).
        // FromPKCS8PublicKey(pubKeyPem).
        Encrypt().
        ToBase64String()

    // 私钥解密
    // private key Decrypt data
    var priKeyPem []byte = []byte("...")
    var deData string = obj.
        FromBase64String(enData).
        FromPrivateKey(priKeyPem).
        // FromPrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS1PrivateKey(priKeyPem).
        // FromPKCS1PrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS8PrivateKey(priKeyPem).
        // FromPKCS8PrivateKeyWithPassword(priKeyPem, password).
        Decrypt().
        ToString()
}
~~~

#### 检测私钥公钥是否匹配 / Check KeyPair
~~~go
func main() {
    var prikeyPem []byte = []byte("...")
    var pubkeyPem []byte = []byte("...")

    // 私钥密码
    // privatekey password
    var password string = ""

    var res bool = elgamal.New().
        // FromPrivateKey(prikeyPem).
        // FromPrivateKeyWithPassword(prikeyPem, password).
        // FromPKCS1PrivateKey(prikeyPem).
        // FromPKCS1PrivateKeyWithPassword(prikeyPem, password).
        FromPKCS8PrivateKey(prikeyPem).
        // FromPKCS8PrivateKeyWithPassword(prikeyPem, password).
        // FromPublicKey(pubkeyPem).
        // FromPKCS1PublicKey(pubkeyPem).
        FromPKCS8PublicKey(pubkeyPem).
        CheckKeyPair()
}
~~~
