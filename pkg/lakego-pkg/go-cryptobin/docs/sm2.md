### SM2 使用文档

#### 包引入 / import pkg
~~~go
import (
    "github.com/deatil/go-cryptobin/cryptobin/sm2"
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
    obj := sm2.New().GenerateKey()

    // 私钥密码
    // privatekey password
    var password string = ""

    // 生成私钥
    // create private key
    var PriKeyPem string = obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword(password).
        // CreatePrivateKeyWithPassword(password, "AES256CBC").
        // CreatePKCS1PrivateKey().
        // CreatePKCS1PrivateKeyWithPassword(password, "AES256CBC").
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword(password, "AES256CBC", "SHA256").
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

    // 设置 UID 值
    // set uid data
    var uid []byte = []byte("")

    // 设置 hash
    // set hash func
    var md5Hash = md5.New

    obj := sm2.New()

    // 私钥签名
    // private key sign data
    // 比如: SM2withSM3 => ... SetSignHash("SM3").Sign() ...
    var priKeyPem []byte = []byte("...")
    sigBase64String = obj.
        FromString(data).
        FromPrivateKey(priKeyPem).
        // FromPrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS1PrivateKey(priKeyPem).
        // FromPKCS1PrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS8PrivateKey(priKeyPem).
        // FromPKCS8PrivateKeyWithPassword(priKeyPem, password).
        // WithUID(uid).
        // SetSignHash("SM3").
        // WithSignHash(md5Hash).
        Sign().
        // SignASN1().
        // SignBytes().
        ToBase64String()

    // 公钥验证
    // public key verify signed data
    var pubKeyPem []byte = []byte("...")
    var res bool = obj.
        FromBase64String(sigBase64String).
        FromPublicKey(pubKeyPem).
        // WithUID(uid).
        // SetSignHash("SM3").
        // WithSignHash(md5Hash).
        Verify([]byte(data)).
        // VerifyASN1([]byte(data)).
        // VerifyBytes([]byte(data)).
        ToVerify()
}
~~~

#### 加密解密 - 公钥加密/私钥解密 / Encrypt with public key
~~~go
func main() {
    obj := sm2.New()

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
        // SetMode 为可选，默认为 C1C3C2
        // SetMode("C1C3C2"). // C1C3C2 | C1C2C3
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
        // SetMode 为可选，默认为 C1C3C2
        // SetMode("C1C3C2"). // C1C3C2 | C1C2C3
        Decrypt().
        ToString()
}
~~~

#### SM2 获取 x, y, d 16进制(Hex)数据 / get x, y, d hex data
~~~go
func main() {
    obj := sm2.New()

    // 获取私钥明文 D
    // get private key D data
    var priKeyPem []byte = []byte("...")
    d := sm2.
        FromPrivateKey(priKeyPem).
        GetPrivateKeyDString()

    // 获取公钥 X, Y 明文数据, 从私钥
    // get public key x data and y data from private key
    var priKeyPem []byte = []byte("...")
    public := sm2.
        FromPrivateKey(priKeyPem).
        MakePublicKey()

    x := public.GetPublicKeyXString()
    y := public.GetPublicKeyYString()

    // 获取公钥 X, Y 明文数据, 从公钥
    // get public key x data and y data from public key
    var pubKeyPem []byte = []byte("...")
    public := sm2.FromPublicKey(pubKeyPem)

    x := public.GetPublicKeyXString()
    y := public.GetPublicKeyYString()
}
~~~

#### SM2 用 x, y 生成公钥，用 d 生成私钥 / use x,y to make public key and use d to make private key
~~~go
func main() {
    sm2PublicKeyX  := "a4b75c4c8c44d11687bdd93c0883e630c895234beb685910efbe27009ad911fa"
    sm2PublicKeyY  := "d521f5e8249de7a405f254a9888cbb8e651fd60c50bd22bd182a4bc7d1261c94"
    sm2PrivateKeyD := "0f495b5445eb59ddecf0626f5ca0041c550584f0189e89d95f8d4c52499ff838"

    obj := sm2.New()
    sm2PriKey := obj.
        FromPublicKeyXYString(sm2PublicKeyX, sm2PublicKeyY).
        CreatePublicKey().
        ToKeyString()
    sm2PubKey := obj.
        FromPrivateKeyString(sm2PrivateKeyD).
        CreatePrivateKey().
        ToKeyString()
}
~~~

#### 检测私钥公钥是否匹配 / Check KeyPair
~~~go
func main() {
    var priKeyPem []byte = []byte("...")
    var pubKeyPem []byte = []byte("...")

    var res bool = sm2.New().
        FromPrivateKey(priKeyPem).
        // FromPrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS1PrivateKey(priKeyPem).
        // FromPKCS1PrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS8PrivateKey(priKeyPem).
        // FromPKCS8PrivateKeyWithPassword(priKeyPem, password).
        FromPublicKey(pubKeyPem).
        CheckKeyPair()
}
~~~

#### 私钥公钥证书解析 / Parse PrivateKey or PublicKey
~~~go
import (
    gmsm2 "github.com/deatil/go-cryptobin/gm/sm2"
    "github.com/deatil/go-cryptobin/cryptobin/sm2"
)

func main() {
    // 私钥解析
    // Parse PrivateKey
    var priKeyPem []byte = []byte("")

    // 私钥密码
    // privatekey password
    var password string = ""

    var parsedPrivateKey *gmsm2.PrivateKey = sm2.New().
        FromPrivateKey(priKeyPem).
        // FromPrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS1PrivateKey(priKeyPem).
        // FromPKCS1PrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS8PrivateKey(priKeyPem).
        // FromPKCS8PrivateKeyWithPassword(priKeyPem, password).
        GetPrivateKey()

    // 公钥解析
    // Parse PublicKey
    var pubKeyPem []byte = []byte("")

    var parsedPublicKey *gmsm2.PublicKey = sm2.New().
        FromPublicKey(pubKeyPem).
        GetPublicKey()
}
~~~

#### 私钥证书格式编码转换 / Change PrivateKey type
~~~go
import (
    "github.com/deatil/go-cryptobin/cryptobin/sm2"
)

func main() {
    // 私钥编码转换
    // PrivateKey change type
    var priKeyPem []byte = []byte("")

    // 私钥密码
    // privatekey password
    var password string = ""

    var newPrivateKey string = sm2.New().
        // FromPrivateKey(priKeyPem).
        // FromPrivateKeyWithPassword(priKeyPem, password).
        // FromPKCS1PrivateKey(priKeyPem).
        FromPKCS1PrivateKeyWithPassword(priKeyPem, password). // PKCS1 有密码证书
        // FromPKCS8PrivateKey(priKeyPem).
        // FromPKCS8PrivateKeyWithPassword(priKeyPem, password).
        // CreatePrivateKey().
        // CreatePrivateKeyWithPassword(password, "AES256CBC").
        // CreatePKCS1PrivateKey().
        // CreatePKCS1PrivateKeyWithPassword(password, "AES256CBC").
        CreatePKCS8PrivateKey(). // 转为 PKCS8 编码
        // CreatePKCS8PrivateKeyWithPassword(password, "AES256CBC", "SHA256").
        ToKeyString()
}
~~~

#### 【招商银行】支付签名验证 / zhaoshang bank check
~~~go
package main

import (
    "fmt"
    "encoding/base64"

    "github.com/deatil/go-cryptobin/cryptobin/sm2"
)

func main() {
    // sm2 签名【招商银行】，
    // 招商银行签名会因为业务不同用的签名方法也会不同，签名方法默认有 SignBytes 和 SignASN1 两种，可根据招商银行给的 demo 选择对应的方法使用
    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, _ := base64.StdEncoding.DecodeString(sm2key)
    sm2data := `{"request":{"body":{"TEST":"中文","TEST2":"!@#$%^&*()","TEST3":12345,"TEST4":[{"arrItem1":"qaz","arrItem2":123,"arrItem3":true,"arrItem4":"中文"}],"buscod":"N02030"},"head":{"funcode":"DCLISMOD","userid":"N003261207"}},"signature":{"sigdat":"__signature_sigdat__"}}`
    sm2userid := "N0032612070000000000000000"
    sm2userid = sm2userid[0:16]
    sm2Sign := sm2.New().
        FromString(sm2data).
        FromPrivateKeyBytes(sm2keyBytes).
        WithUID([]byte(sm2userid)).
        SignBytes().
        // SignASN1().
        ToBase64String()

    // sm2 验证【招商银行】
    sm2signdata := "CDAYcxm3jM+65XKtFNii0tKrTmEbfNdR/Q/BtuQFzm5+luEf2nAhkjYTS2ygPjodpuAkarsNqjIhCZ6+xD4WKA=="
    sm2Verify := sm2.New().
        FromBase64String(sm2signdata).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        WithUID([]byte(sm2userid)).
        VerifyBytes([]byte(sm2data)).
        // VerifyASN1([]byte(sm2data)).
        ToVerify()

    fmt.Println("签名结果：", sm2Sign)
    fmt.Println("验证结果：", sm2Verify)
}
~~~
