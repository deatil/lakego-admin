### jceks/jks 使用文档

* jceks 生成
~~~go
package main

import (
    "fmt"
    "crypto"

    cryptobin_jceks "github.com/deatil/go-cryptobin/jceks"
)

func main() {
    fs := filesystem.New()

    var alias string
    var keypass string
    var privateKey crypto.PrivateKey
    var certs [][]byte
    var cert []byte // 生成证书时的字节数据
    var secretKey []byte

    var passwd string
    var pfxData []byte

    en := cryptobin_jceks.NewJceksEncode()
    en.AddPrivateKey(alias, privateKey, keypass, certs) // 私钥和证书链
    // en.AddTrustedCert(alias, cert) // 证书
    // en.AddSecretKey(alias, secretKey, keypass) // 密钥
    pfxData, err := en.Marshal(passwd)

    fs.Put("./runtime/key/jceks/prikey.jceks", string(pfxData))

    fmt.Println("生成 jceks 成功")
}
~~~

* jceks 解析
~~~go
package main

import (
    "io"
    "fmt"
    "crypto"
    "crypto/x509"

    cryptobin_jceks "github.com/deatil/go-cryptobin/jceks"
)

func main() {
    var jceksData []byte
    var passwd string
    var reader io.Reader

    ks, err := cryptobin_jceks.LoadFromBytes(jceksData, passwd)
    // ks, err := cryptobin_jceks.LoadFromReader(reader, passwd)

    // 获取私钥和证书链
    var alias string
    var keypass string

    var key crypto.PrivateKey
    var certs []*x509.Certificate
    key, certs, err := ks.GetPrivateKeyAndCerts(alias, keypass)

    // 获取证书
    var alias string
    var cert *x509.Certificate
    cert, err := ks.GetCert(alias)

    // 获取密钥
    var alias string
    var secret []byte
    secret, err := ks.GetSecretKey(alias)

    // 列出私钥对应的别名
    var priAliases []string
    priAliases := ks.ListPrivateKeys()

    // 列出证书对应的别名
    var certsAliases []string
    certsAliases := ks.ListCerts()

    // 列出密钥对应的别名
    var secretsAliases []string
    secretsAliases := ks.ListSecretKeys()

    fmt.Println("解析 jceks 成功")
}
~~~

* jks 生成
~~~go
package main

import (
    "fmt"
    "crypto"

    cryptobin_jceks "github.com/deatil/go-cryptobin/jceks"
)

func main() {
    fs := filesystem.New()

    var alias string
    var keypass string
    var privateKey crypto.PrivateKey
    var certs [][]byte
    var cert []byte // 生成证书时的字节数据

    var passwd string
    var pfxData []byte

    en := cryptobin_jceks.NewJksEncode()
    en.AddPrivateKey(alias, privateKey, keypass, certs) // 私钥和证书链
    // en.AddTrustedCert(alias, cert) // 证书
    pfxData, err := en.Marshal(passwd)

    fs.Put("./runtime/key/jceks/prikey.jks", string(pfxData))

    fmt.Println("生成 jks 成功")
}
~~~

* jks 解析
~~~go
package main

import (
    "io"
    "fmt"
    "time"
    "crypto"
    "crypto/x509"

    cryptobin_jceks "github.com/deatil/go-cryptobin/jceks"
)

func main() {
    var jceksData []byte
    var passwd string
    var reader io.Reader

    ks, err := cryptobin_jceks.LoadJksFromBytes(jceksData, passwd)
    // ks, err := cryptobin_jceks.LoadJksFromReader(reader, passwd)

    var alias string

    // 获取私钥
    var keypass string
    var key crypto.PrivateKey
    key, err := ks.GetPrivateKey(alias, keypass)

    // 获取证书链
    var certs []*x509.Certificate
    certs, err := ks.GetCertChain(alias)

    // 获取证书
    var cert *x509.Certificate
    cert, err := ks.GetCert(alias)

    // 获取别名对应时间
    var date time.Time
    date, err := ks.GetCreateDate(alias)

    // 列出私钥对应的别名
    var priAliases []string
    priAliases := ks.ListPrivateKeys()

    // 列出证书对应的别名
    var certsAliases []string
    certsAliases := ks.ListCerts()

    fmt.Println("解析 jceks 成功")
}
~~~
