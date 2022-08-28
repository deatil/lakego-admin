package key

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_sm2 "github.com/deatil/go-cryptobin/cryptobin/sm2"
)

func NewSM2() SM2 {
    fs := filesystem.New()

    path := "./runtime/key/key-pem/sm2"

    return SM2{fs, "123", path, "sm2"}
}

type cSM2 = cryptobin_sm2.SM2

type SM2 struct {
    fs   *filesystem.Filesystem
    pass string
    path string
    name string
}

func (this SM2) Make() {
    obj := cryptobin_sm2.New().GenerateKey()

    this.pkcs8(obj)
    this.pkcs8En(obj)
}

func (this SM2) pkcs8(obj cSM2) {
    // 生成证书
    priKey := obj.
        CreatePrivateKey().
        ToKeyString()
    pubKey := obj.
        CreatePublicKey().
        ToKeyString()

    file := fmt.Sprintf("%s/%s-pkcs8", this.path, this.name)

    this.fs.Put(file, priKey)
    this.fs.Put(file + ".pub", pubKey)
}

func (this SM2) pkcs8En(obj cSM2) {
    // 生成证书
    priKey := obj.
        CreatePrivateKeyWithPassword(this.pass).
        ToKeyString()
    pubKey := obj.
        CreatePublicKey().
        ToKeyString()

    file := fmt.Sprintf("%s/%s-pkcs8-en", this.path, this.name)

    this.fs.Put(file, priKey)
    this.fs.Put(file + ".pub", pubKey)

    // aes
    for _, c := range Pkcs8Ciphers {
        for _, h := range Pkcs8Hashes {
            // 生成证书
            priKey := obj.
                CreatePrivateKeyWithPassword(this.pass, c, h).
                ToKeyString()
            pubKey := obj.
                CreatePublicKey().
                ToKeyString()

            file := fmt.Sprintf("%s/%s-pkcs8-en-%s-%s", this.path, this.name, c, h)

            this.fs.Put(file, priKey)
            this.fs.Put(file + ".pub", pubKey)
        }
    }

    for _, c2 := range Pkcs8PbeCiphers {
        // 生成证书
        priKey := obj.
            CreatePrivateKeyWithPassword(this.pass, c2).
            ToKeyString()
        pubKey := obj.
            CreatePublicKey().
            ToKeyString()

        file := fmt.Sprintf("%s/%s-pkcs8-pbe-en-%s", this.path, this.name, c2)

        this.fs.Put(file, priKey)
        this.fs.Put(file + ".pub", pubKey)
    }

}
