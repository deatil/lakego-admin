package key

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_dsa "github.com/deatil/go-cryptobin/cryptobin/dsa"
)

func NewDSA() DSA {
    fs := filesystem.New()

    path := "./runtime/key/key-pem/dsa"

    return DSA{fs, "123", path, "dsa"}
}

type cDsa = cryptobin_dsa.DSA

var lns = []string{
    "L1024N160",
    "L2048N224",
    "L2048N256",
    "L3072N256",
}

type DSA struct {
    fs   *filesystem.Filesystem
    pass string
    path string
    name string
}

func (this DSA) Make() {
    for _, ln := range lns {
        obj := cryptobin_dsa.New().GenerateKey(ln)

        this.pkcs1(obj, ln)
        this.pkcs8(obj, ln)
        this.pkcs1En(obj, ln)
        this.pkcs8En(obj, ln)
    }
}

func (this DSA) pkcs1(obj cDsa, dir string) {
    // 生成证书
    priKey := obj.
        CreatePrivateKey().
        ToKeyString()
    pubKey := obj.
        CreatePublicKey().
        ToKeyString()

    file := fmt.Sprintf("%s/%s/%s-pkcs1", this.path, dir, this.name)

    this.fs.Put(file, priKey)
    this.fs.Put(file + ".pub", pubKey)
}

func (this DSA) pkcs8(obj cDsa, dir string) {
    // 生成证书
    priKey := obj.
        CreatePKCS8PrivateKey().
        ToKeyString()
    pubKey := obj.
        CreatePKCS8PublicKey().
        ToKeyString()

    file := fmt.Sprintf("%s/%s/%s-pkcs8", this.path, dir, this.name)

    this.fs.Put(file, priKey)
    this.fs.Put(file + ".pub", pubKey)
}

func (this DSA) pkcs1En(obj cDsa, dir string) {
    for _, c := range Pkcs1Ciphers {
        // 生成证书
        priKey := obj.
            CreatePrivateKeyWithPassword(this.pass, c).
            ToKeyString()
        pubKey := obj.
            CreatePublicKey().
            ToKeyString()

        file := fmt.Sprintf("%s/%s/%s-pkcs1-en-%s", this.path, dir, this.name, c)

        this.fs.Put(file, priKey)
        this.fs.Put(file + ".pub", pubKey)
    }
}

func (this DSA) pkcs8En(obj cDsa, dir string) {
    for _, c := range Pkcs8Ciphers {
        for _, h := range Pkcs8Hashes {
            // 生成证书
            priKey := obj.
                CreatePKCS8PrivateKeyWithPassword(this.pass, c, h).
                ToKeyString()
            pubKey := obj.
                CreatePKCS8PublicKey().
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
            CreatePKCS8PublicKey().
            ToKeyString()

        file := fmt.Sprintf("%s/%s/%s-pkcs8-pbe-en-%s", this.path, dir, this.name, c2)

        this.fs.Put(file, priKey)
        this.fs.Put(file + ".pub", pubKey)
    }

}
