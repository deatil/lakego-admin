package key

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_ecdh "github.com/deatil/go-cryptobin/cryptobin/ecdh"
)

func NewGoEcdh() GoEcdh {
    fs := filesystem.New()

    path := "./runtime/key/key-pem/ecdh"

    return GoEcdh{fs, "123", path, "ecdh"}
}

type cGoEcdh = cryptobin_ecdh.Ecdh

var GoEcdhCurves = []string{
    "P521",
    "P384",
    "P256",
    "X25519",
}

type GoEcdh struct {
    fs   *filesystem.Filesystem
    pass string
    path string
    name string
}

func (this GoEcdh) Make() {
    for _, curve := range GoEcdhCurves {
        obj := cryptobin_ecdh.New().SetCurve(curve).GenerateKey()

        this.pkcs8(obj, curve)
        this.pkcs8En(obj, curve)
    }
}

func (this GoEcdh) pkcs8(obj cGoEcdh, name string) {
    // 生成证书
    priKey := obj.
        CreatePrivateKey().
        ToKeyString()
    pubKey := obj.
        CreatePublicKey().
        ToKeyString()

    file := fmt.Sprintf("%s/%s/%s-pkcs8", this.path, name, this.name)

    this.fs.Put(file, priKey)
    this.fs.Put(file + ".pub", pubKey)
}

func (this GoEcdh) pkcs8En(obj cGoEcdh, name string) {
    for _, c := range Pkcs8Ciphers {
        for _, h := range Pkcs8Hashes {
            // 生成证书
            priKey := obj.
                CreatePrivateKeyWithPassword(this.pass, c, h).
                ToKeyString()
            pubKey := obj.
                CreatePublicKey().
                ToKeyString()

            file := fmt.Sprintf("%s/%s/%s-pkcs8-en-%s-%s", this.path, name, this.name, c, h)

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

        file := fmt.Sprintf("%s/%s/%s-pkcs8-pbe-en-%s", this.path, name, this.name, c2)

        this.fs.Put(file, priKey)
        this.fs.Put(file + ".pub", pubKey)
    }

}
