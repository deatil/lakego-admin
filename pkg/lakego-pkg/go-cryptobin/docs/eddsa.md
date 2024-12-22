### EdDSA 使用文档

#### 包引入 / import pkg
~~~go
import (
    "github.com/deatil/go-cryptobin/cryptobin/eddsa"
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
    obj := eddsa.New().GenerateKey()

    // 私钥密码
    // privatekey password
    var password string = ""

    // 生成私钥
    // create private key
    var PriKeyPem string = obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword(password, "AES256CBC").
        ToKeyString()

    // 自定义私钥加密类型
    // use custom encrypt options
    var PriKeyPem string = obj.
        CreatePrivateKeyWithPassword(password, sm2.Opts{
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

    // ctx 数据
    var ctx string = ""

    obj := eddsa.New()

    // 私钥签名
    // private key sign data
    var priKeyPem string = ""
    sigBase64String = obj.
        FromString(data).
        FromPrivateKey([]byte(priKeyPem)).
        // FromPrivateKeyWithPassword([]byte(priKeyPem), password).
        // 其他设置, 默认为 Ed25519 模式
        // SetOptions("Ed25519").
        // SetOptions("Ed25519ph", ctx).
        // SetOptions("Ed25519ctx", ctx).
        Sign().
        ToBase64String()

    // 公钥验证
    // public key verify signed data
    var pubKeyPem string = ""
    var res bool = obj.
        FromBase64String(sigBase64String).
        FromPublicKey([]byte(pubKeyPem)).
        // 其他设置, 默认为 Ed25519 模式
        // SetOptions("Ed25519").
        // SetOptions("Ed25519ph", ctx).
        // SetOptions("Ed25519ctx", ctx).
        Verify([]byte(data)).
        ToVerify()
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

    var res bool = eddsa.New().
        FromPrivateKey(prikeyPem).
        // FromPrivateKeyWithPassword(prikeyPem, password).
        FromPublicKey(pubkeyPem).
        CheckKeyPair()
}
~~~
