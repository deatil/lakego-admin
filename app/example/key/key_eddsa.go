package key

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_eddsa "github.com/deatil/go-cryptobin/cryptobin/eddsa"
)

func NewEdDSA() EdDSA {
    fs := filesystem.New()

    path := "./runtime/key/key-pem/eddsa"

    return EdDSA{fs, "123", path, "eddsa"}
}

type cEdDsa = cryptobin_eddsa.EdDSA

type EdDSA struct {
    fs   *filesystem.Filesystem
    pass string
    path string
    name string
}

func (this EdDSA) Make() {
    obj := cryptobin_eddsa.New().GenerateKey()

    this.pkcs8(obj)
    this.pkcs8En(obj)
}

func (this EdDSA) pkcs8(obj cEdDsa) {
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

func (this EdDSA) pkcs8En(obj cEdDsa) {
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
