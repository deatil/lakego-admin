### bks/uber 使用文档

* bks 生成
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
    var privateKey crypto.PrivateKey
    var publicKey crypto.PublicKey
    var certs [][]byte
    var cert []byte // 生成证书时的字节数据
    var secretKey []byte
    var storedValue []byte
    var plainKey []byte
    var password string

    var passwd string
    var pfxData []byte

    ks := cryptobin_jceks.NewBksEncode()
    ks.AddCert("cert", certBytes, nil);
    ks.AddSecret("stored_value", storedValue, nil);
    ks.AddKeyPrivate("private_key", privateKey, certs);
    ks.AddKeyPublic("public_key", publicKey, nil);
    ks.AddKeySecret("plain_key", plainKey, "AES", nil);
    ks.AddKeyPrivateWithPassword("sealed_private_key", privateKey, password, certs);
    ks.AddKeyPublicWithPassword("sealed_public_key", publicKey, password, nil);
    ks.AddKeySecretWithPassword("sealed_secret_key", secretKey, password, "AES", nil);

    opts := cryptobin_jceks.BKSOpts{
        Version:        1, // 1 | 2
        SaltSize:       20,
        IterationCount: 10000,
    }
    pfxData, err := ks.Marshal(passwd, opts)

    fs.Put("./runtime/key/bks/bks.bksv1", string(pfxData))

    fmt.Println("生成 bks 成功")
}
~~~

* bks 解析
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
    var bksData []byte
    var passwd string
    var reader io.Reader

    ks, err := cryptobin_jceks.LoadBksFromBytes(bksData, passwd)
    // ks, err := cryptobin_jceks.LoadBksFromReader(reader, passwd)

    // 别名及密码
    var alias string
    var sealedPass string

    version := ks.Version()
    storeType := ks.StoreType()

    date, err = ks.GetCreateDate(alias)
    certType, err := ks.GetCertType(alias)
    certChain, err = ks.GetCertChain(alias)
    certChainBytes, err = ks.GetCertChainBytes(alias)

    cert, err := ks.GetCert(alias)
    certBytes, err := ks.GetCertBytes(alias)
    secret, err = ks.GetSecret(alias)

    keyType, err := ks.GetKeyType(alias)
    privateKey, err := ks.GetKeyPrivate(alias)
    publicKey, err := ks.GetKeyPublic(alias)
    secret, err = ks.GetKeySecret(alias)
    privateKey, publicKey, secret, err := ks.GetKey(alias)

    sealedKeyType, err := ks.GetSealedKeyType(alias, sealedPass)
    privateKey, err := ks.GetKeyPrivateWithPassword(alias, sealedPass)
    publicKey, err := ks.GetKeyPublicWithPassword(alias, sealedPass)
    secret, err = ks.GetKeySecretWithPassword(alias, sealedPass)
    privateKey, publicKey, secret, err := ks.GetSealedKey(alias, sealedPass)

    // ===============

    var certsAliases []string
    certsAliases := ks.ListCerts()

    var secretsAliases []string
    secretsAliases := ks.ListSecrets()

    // 未加密的别名列表
    var keysAliases []string
    keysAliases := ks.ListKeys()

    // 加密的别名列表
    var sealedKeysAliases []string
    sealedKeysAliases := ks.ListSealedKeys()

    fmt.Println("解析 bks 成功")
}
~~~

* uber 生成
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
    var privateKey crypto.PrivateKey
    var publicKey crypto.PublicKey
    var certs [][]byte
    var cert []byte // 生成证书时的字节数据
    var secretKey []byte
    var storedValue []byte
    var plainKey []byte
    var password string

    var passwd string
    var pfxData []byte

    ks := cryptobin_jceks.NewUberEncode()
    ks.AddCert("cert", certBytes, nil);
    ks.AddSecret("stored_value", storedValue, nil);
    ks.AddKeyPrivate("private_key", privateKey, certs);
    ks.AddKeyPublic("public_key", publicKey, nil);
    ks.AddKeySecret("plain_key", plainKey, "AES", nil);
    ks.AddKeyPrivateWithPassword("sealed_private_key", privateKey, password, certs);
    ks.AddKeyPublicWithPassword("sealed_public_key", publicKey, password, nil);
    ks.AddKeySecretWithPassword("sealed_secret_key", secretKey, password, "AES", nil);

    opts := cryptobin_jceks.UBEROpts{
        SaltSize:       20,
        IterationCount: 10000,
    }
    pfxData, err := ks.Marshal(passwd, opts)

    fs.Put("./runtime/key/uber/pfx.uber", string(pfxData))

    fmt.Println("生成 uber 成功")
}
~~~

* uber 解析
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
    var uberData []byte
    var passwd string

    ks, err := cryptobin_jceks.LoadUberFromBytes(uberData, passwd)

    // 别名及密码
    var alias string
    var sealedPass string

    version := ks.Version()
    storeType := ks.StoreType()

    date, err = ks.GetCreateDate(alias)
    certType, err := ks.GetCertType(alias)
    certChain, err = ks.GetCertChain(alias)
    certChainBytes, err = ks.GetCertChainBytes(alias)

    cert, err := ks.GetCert(alias)
    certBytes, err := ks.GetCertBytes(alias)
    secret, err = ks.GetSecret(alias)

    keyType, err := ks.GetKeyType(alias)
    privateKey, err := ks.GetKeyPrivate(alias)
    publicKey, err := ks.GetKeyPublic(alias)
    secret, err = ks.GetKeySecret(alias)
    privateKey, publicKey, secret, err := ks.GetKey(alias)

    sealedKeyType, err := ks.GetSealedKeyType(alias, sealedPass)
    privateKey, err := ks.GetKeyPrivateWithPassword(alias, sealedPass)
    publicKey, err := ks.GetKeyPublicWithPassword(alias, sealedPass)
    secret, err = ks.GetKeySecretWithPassword(alias, sealedPass)
    privateKey, publicKey, secret, err := ks.GetSealedKey(alias, sealedPass)

    // ===============

    var certsAliases []string
    certsAliases := ks.ListCerts()

    var secretsAliases []string
    secretsAliases := ks.ListSecrets()

    // 未加密的别名列表
    var keysAliases []string
    keysAliases := ks.ListKeys()

    // 加密的别名列表
    var sealedKeysAliases []string
    sealedKeysAliases := ks.ListSealedKeys()

    fmt.Println("解析 uber 成功")
}
~~~
