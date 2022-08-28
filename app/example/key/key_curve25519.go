package key

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_curve25519 "github.com/deatil/go-cryptobin/cryptobin/dh/curve25519"
)

func NewCurve25519() Curve25519 {
    fs := filesystem.New()

    path := "./runtime/key/key-pem/curve25519"

    return Curve25519{fs, "123", path, "curve25519"}
}

type cCurve25519 = cryptobin_curve25519.Curve25519

type Curve25519 struct {
    fs   *filesystem.Filesystem
    pass string
    path string
    name string
}

func (this Curve25519) Make() {
    obj := cryptobin_curve25519.New().GenerateKey()

    this.pkcs8(obj)
    this.pkcs8En(obj)
}

func (this Curve25519) pkcs8(obj cCurve25519) {
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

func (this Curve25519) pkcs8En(obj cCurve25519) {
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
