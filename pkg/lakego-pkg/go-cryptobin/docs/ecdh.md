### ECDH 使用文档

#### 包引入 / import pkg
~~~go
import (
    "github.com/deatil/go-cryptobin/cryptobin/ecdh"
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
    // 可用参数 [P521 | P384 | P256 | X25519]
    obj := ecdh.New().
        SetCurve("P256").
        GenerateKey()

    // 私钥密码
    // privatekey password
    var psssword string = ""

    // 生成私钥
    // create private key
    var PriKeyPem string = obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword(psssword, "DESEDE3CBC").
        ToKeyString()

    // 自定义私钥加密类型
    // use custom encrypt options
    var PriKeyPem string = obj.
        CreatePrivateKeyWithPassword(psssword, sm2.Opts{
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
        ToKeyString()
}
~~~

#### 生成对称加密密钥
~~~go
func main() {
    var prikeyPem1 string = "..."
    var pubkeyPem1 string = "..."

    var prikeyPem2 string = "..."
    var pubkeyPem2 string = "..."

    // 私钥密码
    // privatekey password
    var psssword string = ""

    var secret1 string = obj.
        FromPrivateKey([]byte(prikeyPem1)).
        // FromPrivateKeyWithPassword([]byte(prikeyPem1), psssword).
        FromPublicKey([]byte(pubkeyPem2)).
        CreateSecretKey().
        ToHexString()

    var secret2 string = obj.
        FromPrivateKey([]byte(prikeyPem2)).
        // FromPrivateKeyWithPassword([]byte(prikeyPem2), psssword).
        FromPublicKey([]byte(pubkeyPem1)).
        CreateSecretKey().
        ToHexString()

    status := false
    if secret1 == secret2) {
        status = true
    }
}
~~~
