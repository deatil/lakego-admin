### ssh 使用文档

* ssh rsa生成使用
~~~go
package main

import (
    "fmt"
    "encoding/pem"

    "github.com/deatil/lakego-filesystem/filesystem"

    cryptobin_ssh "github.com/deatil/go-cryptobin/ssh"
    cryptobin_rsa "github.com/deatil/go-cryptobin/cryptobin/rsa"
)

func main() {
    fs := filesystem.New()

    rsa := cryptobin_rsa.NewRsa().GenerateKey(2048)

    // block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKey(obj.GetPrivateKey(), "comment")
    // block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKeyWithPassword(obj.GetPrivateKey(), "comment", []byte("123"))
    rsaBlock, _ := cryptobin_ssh.MarshalOpenSSHPrivateKeyWithPassword(
        rsa.GetPrivateKey(),
        "comment",
        []byte("123"),
        cryptobin_ssh.Opts{
            // cryptobin_ssh.AES256CBC
            Cipher:  cryptobin_ssh.AES256CTR,
            KDFOpts: cryptobin_ssh.BcryptOpts{
                SaltSize: 16,
                Rounds:   16,
            },
        },
    )
    rsaBlockkeyData := pem.EncodeToMemory(rsaBlock)

    fs.Put("./runtime/key/ssh/rsa-en", string(rsaBlockkeyData))

    fmt.Println("生成成功")
}

~~~

* ssh rsa解析使用
~~~go
package main

import (
    "fmt"
    go_rsa "crypto/rsa"
    "encoding/pem"

    "github.com/deatil/lakego-filesystem/filesystem"

    cryptobin_ssh "github.com/deatil/go-cryptobin/ssh"
    cryptobin_rsa "github.com/deatil/go-cryptobin/cryptobin/rsa"
)

func main() {
    fs := filesystem.New()

    // ssh
    sshRsaEn, _ := fs.Get("./runtime/key/ssh/rsa-en")
    sshRsaEnBlock, _ := pem.Decode([]byte(sshRsaEn))
    // sshRsaKey, comment, err := cryptobin_ssh.ParseOpenSSHPrivateKey(sshRsaEnBlock.Bytes)
    sshRsaKey, comment, err := cryptobin_ssh.ParseOpenSSHPrivateKeyWithPassword(sshRsaEnBlock.Bytes, []byte("123"))

    if err == nil {
        sshRsaPriKey := cryptobin_rsa.NewRsa().
            WithPrivateKey(sshRsaKey.(*go_rsa.PrivateKey)).
            CreatePKCS8PrivateKey().
            ToKeyString()

        fs.Put("./runtime/key/ssh/rsa-key-pkcs8", sshRsaPriKey)
    } else {
        fs.Put("./runtime/key/ssh/rsa-key-pkcs8", err.Error())
    }

    fmt.Println("解析 key 成功")
    fmt.Println("证书 comment 为: " + comment)
}

~~~

* ssh 生成公钥
~~~go
package main

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"

    "github.com/deatil/go-cryptobin/ssh"
    cryptobin_rsa "github.com/deatil/go-cryptobin/cryptobin/rsa"
)

func main() {
    fs := filesystem.New()

    sshRsaPubKey := cryptobin_rsa.New().
        GenerateKey().
        GetPublicKey()
    sshPubKey, _ := ssh.NewPublicKey(sshRsaPubKey)
    sshAuthorizedKey := ssh.MarshalAuthorizedKeyWithComment(sshPubKey, "abc@email.com")

    fs.Put("./runtime/key/ssh/pub/rsa.pub", string(sshAuthorizedKey))

	fmt.Println("生成公钥成功")
}
~~~

* ssh 解析
~~~go
package main

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"

    "github.com/deatil/go-cryptobin/ssh"
    cryptobin_rsa "github.com/deatil/go-cryptobin/cryptobin/rsa"
)

func main() {
    fs := filesystem.New()

    sshPri1, _ := fs.Get("./runtime/key/ssh/pub/dsa.pub")
    sshPubKey, sshcomment, sshoptions, sshrest, ssherr := ssh.ParseAuthorizedKey([]byte(sshPri1))

    var sshAuthorizedKey []byte

    if ssherr == nil {
        sshAuthorizedKey = ssh.MarshalAuthorizedKeyWithComment(sshPubKey, "abc@qq.com")

        fs.Put("./runtime/key/ssh/pub/dsa_2.pub", string(sshAuthorizedKey))
    }

	fmt.Println("解析公钥成功")
}
~~~

