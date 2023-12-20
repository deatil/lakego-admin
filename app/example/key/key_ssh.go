package key

import (
    "fmt"
    "errors"
    "crypto"
    "encoding/pem"
    "crypto/rand"
    go_rsa "crypto/rsa"
    go_ecdsa "crypto/ecdsa"
    go_eddsa "crypto/ed25519"
    "golang.org/x/crypto/ssh"

    "github.com/deatil/go-cryptobin/gm/sm2"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_ssh "github.com/deatil/go-cryptobin/ssh"
    cryptobin_sm2 "github.com/deatil/go-cryptobin/cryptobin/sm2"
    cryptobin_rsa "github.com/deatil/go-cryptobin/cryptobin/rsa"
    cryptobin_ecdsa "github.com/deatil/go-cryptobin/cryptobin/ecdsa"
    cryptobin_eddsa "github.com/deatil/go-cryptobin/cryptobin/eddsa"
)

var sshcurves = []string{
    "P521",
    "P384",
    "P256",
}

func MakeAllSSHKey() {
    // 无密码生成
    for _, curve := range sshcurves {
        MakeEcdsaUnenSSHKey(curve)
    }

    MakeRsaUnenSSHKey()
    MakeEdDsaUnenSSHKey()
    MakeSM2UnenSSHKey()

    // ==============

    // 密码生成
    for _, c := range SSHKeyCiphers {
        for _, curve := range sshcurves {
            MakeEcdsaSSHKey(c, curve)
        }

        MakeRsaSSHKey(c)
        MakeEdDsaSSHKey(c)
        MakeSM2SSHKey(c)
    }

    // ==============

    // 官方解析
    for _, goc := range SSHKeyGoCiphers {
        for _, curve := range sshcurves {
            MakeEcdsaSSHKey2(goc, curve)
        }

        MakeRsaSSHKey2(goc)
        MakeEdDsaSSHKey2(goc)
    }
}

func MakeRsaUnenSSHKey() {
    fs := filesystem.New()

    obj := cryptobin_rsa.NewRsa().GenerateKey(2048)

    block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKey(rand.Reader, obj.GetPrivateKey(), "ssh")
    blockkeyData := pem.EncodeToMemory(block)
    fs.Put("./runtime/key/ssh/rsa-unen-sshkey", string(blockkeyData))

    sshRsaKey, comment, err := cryptobin_ssh.ParseOpenSSHPrivateKey(block.Bytes)
    if err == nil {
        sshRsaPriKey := cryptobin_rsa.NewRsa().
            WithPrivateKey(sshRsaKey.(*go_rsa.PrivateKey)).
            CreatePKCS8PrivateKey().
            ToKeyString()

        fs.Put("./runtime/key/ssh/rsa-unen-sshkey-pkcs8", sshRsaPriKey)
    } else {
        fs.Put("./runtime/key/ssh/rsa-unen-sshkey-pkcs8", err.Error())
    }

    fmt.Println("Rsa 证书 comment 为: " + comment)
}

// curve := P521 | P384 | P256
func MakeEcdsaUnenSSHKey(curve string) {
    fs := filesystem.New()

    // P521 | P384 | P256
    obj := cryptobin_ecdsa.New().
        SetCurve(curve).
        GenerateKey()

    block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKey(
        rand.Reader,
        obj.GetPrivateKey(),
        "ssh",
    )
    rsaBlockkeyData := pem.EncodeToMemory(block)
    fs.Put("./runtime/key/ssh/ecdsa-unen-sshkey-"+curve, string(rsaBlockkeyData))

    sshKey, _, err := cryptobin_ssh.ParseOpenSSHPrivateKey(block.Bytes)
    if err == nil {
        sshPriKey := cryptobin_ecdsa.New().
            WithPrivateKey(sshKey.(*go_ecdsa.PrivateKey)).
            CreatePKCS8PrivateKey().
            ToKeyString()

        fs.Put("./runtime/key/ssh/ecdsa-unen-sshkey-"+curve+"-pkcs8", sshPriKey)
    } else {
        fs.Put("./runtime/key/ssh/ecdsa-unen-sshkey-"+curve+"-pkcs8", err.Error())
    }
}

func MakeEdDsaUnenSSHKey() {
    fs := filesystem.New()

    obj := cryptobin_eddsa.New().
        GenerateKey()

    block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKey(
        rand.Reader,
        obj.GetPrivateKey(),
        "ssh",
    )
    blockkeyData := pem.EncodeToMemory(block)
    fs.Put("./runtime/key/ssh/eddsa-unen-sshkey", string(blockkeyData))

    sshKey, _, err := cryptobin_ssh.ParseOpenSSHPrivateKey(block.Bytes)
    if err == nil {
        sshPriKey := cryptobin_eddsa.New().
            WithPrivateKey(sshKey.(go_eddsa.PrivateKey)).
            CreatePrivateKey().
            ToKeyString()

        fs.Put("./runtime/key/ssh/eddsa-unen-sshkey-pkcs8", sshPriKey)
    } else {
        fs.Put("./runtime/key/ssh/eddsa-unen-sshkey-pkcs8", err.Error())
    }
}

func MakeSM2UnenSSHKey() {
    fs := filesystem.New()

    obj := cryptobin_sm2.New().
        GenerateKey()

    block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKey(
        rand.Reader,
        obj.GetPrivateKey(),
        "ssh",
    )
    blockkeyData := pem.EncodeToMemory(block)
    fs.Put("./runtime/key/ssh/sm2-unen-sshkey", string(blockkeyData))

    sshPriKey := ""

    sshKey, _, err := cryptobin_ssh.ParseOpenSSHPrivateKey(block.Bytes)
    if err == nil {
        sshPriKey = cryptobin_sm2.New().
            WithPrivateKey(sshKey.(*sm2.PrivateKey)).
            CreatePrivateKey().
            ToKeyString()

    } else {
        sshPriKey = err.Error()
    }

    fs.Put("./runtime/key/ssh/sm2-unen-sshkey-pkcs8", sshPriKey)
}

// rsaName := "AES256CBC"
func MakeRsaSSHKey(rsaName string) {
    fs := filesystem.New()

    rsa := cryptobin_rsa.NewRsa().GenerateKey(2048)

    // block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKey(obj.GetPrivateKey(), "ssh")
    // block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKeyWithPassword(obj.GetPrivateKey(), "ssh", []byte("123"))
    rsaBlock, _ := cryptobin_ssh.MarshalOpenSSHPrivateKeyWithPassword(
        rand.Reader,
        rsa.GetPrivateKey(),
        "ssh",
        []byte("123"),
        cryptobin_ssh.Opts{
            Cipher:  cryptobin_ssh.GetCipherFromName(rsaName),
            KDFOpts: cryptobin_ssh.BcryptOpts{
                SaltSize: 16,
                Rounds:   16,
            },
        },
    )
    rsaBlockkeyData := pem.EncodeToMemory(rsaBlock)
    fs.Put("./runtime/key/ssh/rsa-en-"+rsaName+"", string(rsaBlockkeyData))

    sshRsaKey, _, err := cryptobin_ssh.ParseOpenSSHPrivateKeyWithPassword(rsaBlock.Bytes, []byte("123"))
    if err == nil {
        sshRsaPriKey := cryptobin_rsa.NewRsa().
            WithPrivateKey(sshRsaKey.(*go_rsa.PrivateKey)).
            CreatePKCS8PrivateKey().
            ToKeyString()

        fs.Put("./runtime/key/ssh/rsa-key-"+rsaName+"-pkcs8", sshRsaPriKey)
    } else {
        fs.Put("./runtime/key/ssh/rsa-key-"+rsaName+"-pkcs8", err.Error())
    }
}

// name := "AES256CBC"
// curve := P521 | P384 | P256
func MakeEcdsaSSHKey(name string, curve string) {
    fs := filesystem.New()

    // P521 | P384 | P256
    obj := cryptobin_ecdsa.New().
        SetCurve(curve).
        GenerateKey()

    block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKeyWithPassword(
        rand.Reader,
        obj.GetPrivateKey(),
        "ssh",
        []byte("123"),
        cryptobin_ssh.Opts{
            Cipher:  cryptobin_ssh.GetCipherFromName(name),
            KDFOpts: cryptobin_ssh.BcryptOpts{
                SaltSize: 16,
                Rounds:   16,
            },
        },
    )
    rsaBlockkeyData := pem.EncodeToMemory(block)
    fs.Put("./runtime/key/ssh/ecdsa-en-"+curve+"-"+name+"", string(rsaBlockkeyData))

    sshKey, _, err := cryptobin_ssh.ParseOpenSSHPrivateKeyWithPassword(block.Bytes, []byte("123"))
    if err == nil {
        sshPriKey := cryptobin_ecdsa.New().
            WithPrivateKey(sshKey.(*go_ecdsa.PrivateKey)).
            CreatePKCS8PrivateKey().
            ToKeyString()

        fs.Put("./runtime/key/ssh/ecdsa-key-"+curve+"-"+name+"-pkcs8", sshPriKey)
    } else {
        fs.Put("./runtime/key/ssh/ecdsa-key-"+curve+"-"+name+"-pkcs8", err.Error())
    }
}

// name := "AES256CBC"
func MakeEdDsaSSHKey(name string) {
    fs := filesystem.New()

    obj := cryptobin_eddsa.New().
        GenerateKey()

    block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKeyWithPassword(
        rand.Reader,
        obj.GetPrivateKey(),
        "ssh",
        []byte("123"),
        cryptobin_ssh.Opts{
            Cipher:  cryptobin_ssh.GetCipherFromName(name),
            KDFOpts: cryptobin_ssh.BcryptOpts{
                SaltSize: 16,
                Rounds:   16,
            },
        },
    )
    blockkeyData := pem.EncodeToMemory(block)
    fs.Put("./runtime/key/ssh/eddsa-en-"+name+"", string(blockkeyData))

    sshKey, _, err := cryptobin_ssh.ParseOpenSSHPrivateKeyWithPassword(block.Bytes, []byte("123"))
    if err == nil {
        sshPriKey := cryptobin_eddsa.New().
            WithPrivateKey(sshKey.(go_eddsa.PrivateKey)).
            CreatePrivateKey().
            ToKeyString()

        fs.Put("./runtime/key/ssh/eddsa-key-"+name+"-pkcs8", sshPriKey)
    } else {
        fs.Put("./runtime/key/ssh/eddsa-key-"+name+"-pkcs8", err.Error())
    }
}

// name := "SM4CBC" | "SM4CTR"
func MakeSM2SSHKey(name string) {
    fs := filesystem.New()

    obj := cryptobin_sm2.New().
        GenerateKey()

    block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKeyWithPassword(
        rand.Reader,
        obj.GetPrivateKey(),
        "ssh",
        []byte("123"),
        cryptobin_ssh.Opts{
            Cipher:  cryptobin_ssh.GetCipherFromName(name),
            KDFOpts: cryptobin_ssh.BcryptOpts{
                SaltSize: 16,
                Rounds:   16,
            },
        },
    )
    blockkeyData := pem.EncodeToMemory(block)
    fs.Put("./runtime/key/ssh/sm2-en-"+name+"", string(blockkeyData))

    sshPriKey := ""

    sshKey, _, err := cryptobin_ssh.ParseOpenSSHPrivateKeyWithPassword(block.Bytes, []byte("123"))
    if err == nil {
        sshPriKey = cryptobin_sm2.New().
            WithPrivateKey(sshKey.(*sm2.PrivateKey)).
            CreatePrivateKey().
            ToKeyString()

    } else {
        sshPriKey = err.Error()
    }

    fs.Put("./runtime/key/ssh/sm2-key-"+name+"-pkcs8", sshPriKey)
}

// rsaName := "AES256CBC" | "AES256CTR"
func MakeRsaSSHKey2(rsaName string) {
    fs := filesystem.New()

    // ssh
    sshRsaEn, _ := fs.Get("./runtime/key/ssh/rsa-en-"+rsaName)
    sshRsaKey, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(sshRsaEn), []byte("123"))
    if err == nil {
        sshRsaPriKey := cryptobin_rsa.NewRsa().
            WithPrivateKey(sshRsaKey.(*go_rsa.PrivateKey)).
            CreatePKCS8PrivateKey().
            ToKeyString()

        fs.Put("./runtime/key/ssh/rsa-key-crypto_ssh-"+rsaName+"-pkcs8", sshRsaPriKey)
    } else {
        fs.Put("./runtime/key/ssh/rsa-key-crypto_ssh-"+rsaName+"-pkcs8", err.Error())
    }

}

// name := "AES256CBC" | "AES256CTR"
func MakeEdDsaSSHKey2(name string) {
    fs := filesystem.New()

    // ssh
    sshKeyEn, _ := fs.Get("./runtime/key/ssh/eddsa-en-"+name)
    sshKey, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(sshKeyEn), []byte("123"))
    if err == nil {
        prikey := sshKey.(*go_eddsa.PrivateKey)
        sshPriKey := cryptobin_eddsa.New().
            WithPrivateKey(*prikey).
            CreatePrivateKey().
            ToKeyString()

        fs.Put("./runtime/key/ssh/eddsa-key-crypto_ssh-"+name+"-pkcs8", sshPriKey)
    } else {
        fs.Put("./runtime/key/ssh/eddsa-key-crypto_ssh-"+name+"-pkcs8", err.Error())
    }

}

// name := "AES256CBC" | "AES256CTR"
// curve := P521 | P384 | P256
func MakeEcdsaSSHKey2(name string, curve string) {
    fs := filesystem.New()

    // ssh
    sshKeyEn, _ := fs.Get("./runtime/key/ssh/ecdsa-en-"+curve+"-"+name)
    sshKey, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(sshKeyEn), []byte("123"))
    if err == nil {
        sshRsaPriKey := cryptobin_ecdsa.New().
            WithPrivateKey(sshKey.(*go_ecdsa.PrivateKey)).
            CreatePKCS8PrivateKey().
            ToKeyString()

        fs.Put("./runtime/key/ssh/ecdsa-key-crypto_ssh-"+curve+"-"+name+"-pkcs8", sshRsaPriKey)
    } else {
        fs.Put("./runtime/key/ssh/ecdsa-key-crypto_ssh-"+curve+"-"+name+"-pkcs8", err.Error())
    }

}

// file 路径
// sshFile := "./runtime/key/webssh/id_rsa"
func ParseSSHKey(file string, pass string) (string, string, error) {
    fs := filesystem.New()

    fileData, _ := fs.Get(file)

    var block *pem.Block
    if block, _ = pem.Decode([]byte(fileData)); block == nil {
        return "", "", errors.New("ssh: data is not pem")
    }

    var sshKey crypto.PrivateKey
    var comment string
    var err error

    if pass != "" {
        sshKey, comment, err = cryptobin_ssh.ParseOpenSSHPrivateKeyWithPassword(block.Bytes, []byte(pass))
    } else {
        sshKey, comment, err = cryptobin_ssh.ParseOpenSSHPrivateKey(block.Bytes)
    }

    if err != nil {
        return "", "", errors.New("ssh: sshKey is error. " + err.Error())
    }

    sshkeyData := fmt.Sprintf("%#v", sshKey)
    return sshkeyData, comment, nil
}
