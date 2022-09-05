package key

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_ecdh "github.com/deatil/go-cryptobin/cryptobin/dh/ecdh"
)

func NewEcdh() Ecdh {
    fs := filesystem.New()

    path := "./runtime/key/key-pem/dh/ecdh"

    return Ecdh{fs, "123", path, "ecdh"}
}

var ecurves = []string{
    "P521",
    "P384",
    "P256",
    "P224",
}

type Ecdh struct {
    fs   *filesystem.Filesystem
    pass string
    path string
    name string
}

func (this Ecdh) Make() {
    for _, curve := range ecurves {
        obj := cryptobin_ecdh.New().
            SetCurve(curve).
            GenerateKey()

        this.pkcs8(obj, curve)
        this.pkcs8En(obj, curve)
    }
}

func (this Ecdh) pkcs8(obj cryptobin_ecdh.Ecdh, dir string) {
    // 生成证书
    priKey := obj.
        CreatePrivateKey().
        ToKeyString()
    pubKey := obj.
        CreatePublicKey().
        ToKeyString()

    file := fmt.Sprintf("%s/%s/%s-pkcs8", this.path, dir, this.name)

    this.fs.Put(file, priKey)
    this.fs.Put(file + ".pub", pubKey)
}

func (this Ecdh) pkcs8En(obj cryptobin_ecdh.Ecdh, dir string) {
    for _, c := range Pkcs8Ciphers {
        for _, h := range Pkcs8Hashes {
            // 生成证书
            priKey := obj.
                CreatePrivateKeyWithPassword(this.pass, c, h).
                ToKeyString()
            pubKey := obj.
                CreatePublicKey().
                ToKeyString()

            file := fmt.Sprintf("%s/%s/%s-pkcs8-en-%s-%s", this.path, dir, this.name, c, h)

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

        file := fmt.Sprintf("%s/%s/%s-pkcs8-pbe-en-%s", this.path, dir, this.name, c2)

        this.fs.Put(file, priKey)
        this.fs.Put(file + ".pub", pubKey)
    }

}
