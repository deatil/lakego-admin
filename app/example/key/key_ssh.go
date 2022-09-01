package key

import (
    "encoding/pem"
    go_rsa "crypto/rsa"
    go_ecdsa "crypto/ecdsa"
    go_eddsa "crypto/ed25519"
    "golang.org/x/crypto/ssh"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_ssh "github.com/deatil/go-cryptobin/ssh"
    cryptobin_rsa "github.com/deatil/go-cryptobin/cryptobin/rsa"
    cryptobin_ecdsa "github.com/deatil/go-cryptobin/cryptobin/ecdsa"
    cryptobin_eddsa "github.com/deatil/go-cryptobin/cryptobin/eddsa"
)

func MakeUnenSSHKey() {
    fs := filesystem.New()

    obj := cryptobin_rsa.NewRsa().GenerateKey(2048)

    block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKey(obj.GetPrivateKey(), "ssh")
    blockkeyData := pem.EncodeToMemory(block)
    fs.Put("./runtime/key/ssh/rsa-unen-sshkey", string(blockkeyData))

    sshRsaKey, err := cryptobin_ssh.ParseOpenSSHPrivateKey(block.Bytes)
    if err == nil {
        sshRsaPriKey := cryptobin_rsa.NewRsa().
            WithPrivateKey(sshRsaKey.(*go_rsa.PrivateKey)).
            CreatePKCS8PrivateKey().
            ToKeyString()

        fs.Put("./runtime/key/ssh/rsa-unen-sshkey-pkcs8", sshRsaPriKey)
    } else {
        fs.Put("./runtime/key/ssh/rsa-unen-sshkey-pkcs8", err.Error())
    }
}

// rsaName := "AES256CBC"
func MakeSSHKey(rsaName string) {
    fs := filesystem.New()

    rsa := cryptobin_rsa.NewRsa().GenerateKey(2048)

    // block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKey(obj.GetPrivateKey(), "ssh")
    // block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKeyWithPassword(obj.GetPrivateKey(), "ssh", "123")
    rsaBlock, _ := cryptobin_ssh.MarshalOpenSSHPrivateKeyWithPassword(
        rsa.GetPrivateKey(),
        "ssh",
        []byte("123"),
        cryptobin_ssh.Options{
            Cipher:  cryptobin_ssh.GetCipherFromName(rsaName),
            KDFOpts: cryptobin_ssh.BcryptOpts{
                SaltSize: 16,
                Rounds:   16,
            },
        },
    )
    rsaBlockkeyData := pem.EncodeToMemory(rsaBlock)
    fs.Put("./runtime/key/ssh/rsa-en-"+rsaName+"", string(rsaBlockkeyData))

    sshRsaKey, err := cryptobin_ssh.ParseOpenSSHPrivateKeyWithPassword(rsaBlock.Bytes, []byte("123"))
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
        WithCurve(curve).
        GenerateKey()

    block, _ := cryptobin_ssh.MarshalOpenSSHPrivateKeyWithPassword(
        obj.GetPrivateKey(),
        "ssh",
        []byte("123"),
        cryptobin_ssh.Options{
            Cipher:  cryptobin_ssh.GetCipherFromName(name),
            KDFOpts: cryptobin_ssh.BcryptOpts{
                SaltSize: 16,
                Rounds:   16,
            },
        },
    )
    rsaBlockkeyData := pem.EncodeToMemory(block)
    fs.Put("./runtime/key/ssh/ecdsa-en-"+curve+"-"+name+"", string(rsaBlockkeyData))

    sshKey, err := cryptobin_ssh.ParseOpenSSHPrivateKeyWithPassword(block.Bytes, []byte("123"))
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
        obj.GetPrivateKey(),
        "ssh",
        []byte("123"),
        cryptobin_ssh.Options{
            Cipher:  cryptobin_ssh.GetCipherFromName(name),
            KDFOpts: cryptobin_ssh.BcryptOpts{
                SaltSize: 16,
                Rounds:   16,
            },
        },
    )
    blockkeyData := pem.EncodeToMemory(block)
    fs.Put("./runtime/key/ssh/eddsa-en-"+name+"", string(blockkeyData))

    sshKey, err := cryptobin_ssh.ParseOpenSSHPrivateKeyWithPassword(block.Bytes, []byte("123"))
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

// rsaName := "AES256CBC" | "AES256CTR"
func MakeSSHKey2(rsaName string) {
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
func MakeEcdsaSSHKey2(name string) {
    fs := filesystem.New()

    // ssh
    sshKeyEn, _ := fs.Get("./runtime/key/ssh/ecdsa-en-"+name)
    sshKey, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(sshKeyEn), []byte("123"))
    if err == nil {
        sshRsaPriKey := cryptobin_ecdsa.New().
            WithPrivateKey(sshKey.(*go_ecdsa.PrivateKey)).
            CreatePKCS8PrivateKey().
            ToKeyString()

        fs.Put("./runtime/key/ssh/ecdsa-key-crypto_ssh-"+name+"-pkcs8", sshRsaPriKey)
    } else {
        fs.Put("./runtime/key/ssh/ecdsa-key-crypto_ssh-"+name+"-pkcs8", err.Error())
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
func MakeEcdsaSSHKey3(name string, curve string) {
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
