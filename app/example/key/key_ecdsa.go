package key

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_ecdsa "github.com/deatil/go-cryptobin/cryptobin/ecdsa"
)

func NewEcdsa() Ecdsa {
    fs := filesystem.New()

    path := "./runtime/key/key-pem/ecdsa"

    return Ecdsa{fs, "123", path, "ecdsa"}
}

var curves = []string{
    "P521",
    "P384",
    "P256",
    "P224",
}

type Ecdsa struct {
    fs   *filesystem.Filesystem
    pass string
    path string
    name string
}

func (this Ecdsa) Make() {
    for _, curve := range curves {
        obj := cryptobin_ecdsa.New().
            SetCurve(curve).
            GenerateKey()

        this.pkcs1(obj, curve)
        this.pkcs8(obj, curve)
        this.pkcs1En(obj, curve)
        this.pkcs8En(obj, curve)
    }
}

func (this Ecdsa) pkcs1(obj cryptobin_ecdsa.Ecdsa, dir string) {
    // 生成证书
    priKey := obj.
        CreatePKCS1PrivateKey().
        ToKeyString()
    pubKey := obj.
        CreatePublicKey().
        ToKeyString()

    file := fmt.Sprintf("%s/%s/%s-pkcs1", this.path, dir, this.name)

    this.fs.Put(file, priKey)
    this.fs.Put(file + ".pub", pubKey)
}

func (this Ecdsa) pkcs8(obj cryptobin_ecdsa.Ecdsa, dir string) {
    // 生成证书
    priKey := obj.
        CreatePKCS8PrivateKey().
        ToKeyString()
    pubKey := obj.
        CreatePublicKey().
        ToKeyString()

    file := fmt.Sprintf("%s/%s/%s-pkcs8", this.path, dir, this.name)

    this.fs.Put(file, priKey)
    this.fs.Put(file + ".pub", pubKey)
}

func (this Ecdsa) pkcs1En(obj cryptobin_ecdsa.Ecdsa, dir string) {
    for _, c := range Pkcs1Ciphers {
        // 生成证书
        priKey := obj.
            CreatePKCS1PrivateKeyWithPassword(this.pass, c).
            ToKeyString()
        pubKey := obj.
            CreatePublicKey().
            ToKeyString()

        file := fmt.Sprintf("%s/%s/%s-pkcs1-en-%s", this.path, dir, this.name, c)

        this.fs.Put(file, priKey)
        this.fs.Put(file + ".pub", pubKey)
    }
}

func (this Ecdsa) pkcs8En(obj cryptobin_ecdsa.Ecdsa, dir string) {
    for _, c := range Pkcs8Ciphers {
        for _, h := range Pkcs8Hashes {
            // 生成证书
            priKey := obj.
                CreatePKCS8PrivateKeyWithPassword(this.pass, c, h).
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
            CreatePKCS8PrivateKeyWithPassword(this.pass, c2).
            ToKeyString()
        pubKey := obj.
            CreatePublicKey().
            ToKeyString()

        file := fmt.Sprintf("%s/%s/%s-pkcs8-pbe-en-%s", this.path, dir, this.name, c2)

        this.fs.Put(file, priKey)
        this.fs.Put(file + ".pub", pubKey)
    }

}
