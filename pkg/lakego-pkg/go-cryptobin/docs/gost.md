### Gost 使用文档

实现的 GOST 3410 非对称签名验证

#### 包引入 / import pkg
~~~go
import (
    "github.com/deatil/go-cryptobin/cryptobin/gost"
)
~~~

#### 数据输入方式 / data input funcs
~~~go
FromBytes(data []byte)
FromString(data string)
FromBase64String(data string)
FromHexString(data string)
~~~

#### 数据输出 / data output funcs
~~~go
ToBytes()
ToString()
ToBase64String()
ToHexString()
~~~

#### VKO 数据输出 / VKO output funcs
~~~go
ToSecretBytes()
ToSecretString()
ToSecretBase64String()
ToSecretHexString()
~~~

#### 获取 error / get error
~~~go
Error()
~~~

#### 生成证书 / make keys
~~~go
func main() {
    obj := gost.New().GenerateKey()

    // 私钥密码
    // privatekey password
    var password string = ""

    // 生成私钥
    // create private key
    var PriKeyPem string = obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword(password).
        // CreatePrivateKeyWithPassword(password, "AES256CBC").
        ToKeyString()

    // 自定义私钥加密类型
    // use custom encrypt options
    var PriKeyPem string = obj.
        CreatePrivateKeyWithPassword(password, gost.Opts{
            Cipher:  gost.GetCipherFromName("AES256CBC"),
            KDFOpts: gost.ScryptOpts{
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

    // 数据签名类型
    // hash name type
    // gost: GOST34112012256 | GOST34112012512
    var hashName string = "GOST34112012256"

    obj := gost.New()

    // 私钥签名
    // private key sign data
    var prikeyPem []byte = []byte("...")
    sigBase64String = obj.
        FromString(data).
        FromPrivateKey(prikeyPem).
        // FromPrivateKeyWithPassword(prikeyPem, password).
        // SetSignHash(hashName).
        Sign().
        // SignASN1().
        ToBase64String()

    // 公钥验证
    // public key verify signed data
    var pubkeyPem []byte = []byte("...")
    var res bool = obj.
        FromBase64String(sigBase64String).
        FromPublicKey(pubkeyPem).
        // SetSignHash(hashName).
        Verify([]byte(data)).
        // VerifyASN1([]byte(data)).
        ToVerify()
}
~~~

#### 检测私钥公钥是否匹配 / Check KeyPair
~~~go
func main() {
    var prikeyPem []byte = []byte("...")
    var pubkeyPem []byte = []byte("...")

    var res bool = gost.New().
        FromPrivateKey(prikeyPem).
        // FromPrivateKeyWithPassword(prikeyPem, password).
        FromPublicKey(pubkeyPem).
        CheckKeyPair()
}
~~~

#### 生成 VKO 密钥
~~~go
func main() {
    var prikeyPem1 []byte = []byte("...")
    var pubkeyPem1 []byte = []byte("...")

    var prikeyPem2 []byte = []byte("...")
    var pubkeyPem2 []byte = []byte("...")

    // 私钥密码
    // privatekey password
    var password string = ""

    // ukm 数据
    // ukm data
    var ukm []byte = []byte("...")

    var secret1 string = obj.
        FromPrivateKey(prikeyPem1).
        // FromPrivateKeyWithPassword(prikeyPem1, password).
        FromPublicKey(pubkeyPem2).
        KEK(ukm).
        // KEK2001(ukm).
        // KEK2012256(ukm).
        // KEK2012512(ukm).
        ToSecretString()

    var secret2 string = obj.
        FromPrivateKey(prikeyPem2).
        // FromPrivateKeyWithPassword(prikeyPem2, password).
        FromPublicKey(pubkeyPem1).
        KEK(ukm).
        // KEK2001(ukm).
        // KEK2012256(ukm).
        // KEK2012512(ukm).
        ToSecretString()

    status := false
    if secret1 == secret2) {
        status = true
    }
}
~~~
