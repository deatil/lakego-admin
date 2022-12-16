package key

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_rsa "github.com/deatil/go-cryptobin/cryptobin/rsa"
)

func NewRsa() Rsa {
    fs := filesystem.New()

    return Rsa{fs, "123"}
}

var bits = []int{
    512,
    1024,
    2048,
    4096,
}

type Rsa struct {
    fs   *filesystem.Filesystem
    pass string
}

func (this Rsa) Make() {
    for _, bit := range bits {
        rsa := cryptobin_rsa.NewRsa().GenerateKey(bit)

        this.pkcs1(rsa, bit)
        this.pkcs8(rsa, bit)
        this.pkcs1En(rsa, bit)
        this.pkcs8En(rsa, bit)
    }
}

func (this Rsa) pkcs1(rsa cryptobin_rsa.Rsa, bit int) {
    // 生成证书
    priKey := rsa.
        CreatePKCS1PrivateKey().
        ToKeyString()
    pubKey := rsa.
        CreatePKCS1PublicKey().
        ToKeyString()

    file := fmt.Sprintf("./runtime/key/key-pem/rsa/%d/rsa-pkcs1", bit)

    this.fs.Put(file, priKey)
    this.fs.Put(file + ".pub", pubKey)
}

func (this Rsa) pkcs8(rsa cryptobin_rsa.Rsa, bit int) {
    // 生成证书
    priKey := rsa.
        CreatePKCS8PrivateKey().
        ToKeyString()
    pubKey := rsa.
        CreatePKCS8PublicKey().
        ToKeyString()

    file := fmt.Sprintf("./runtime/key/key-pem/rsa/%d/rsa-pkcs8", bit)

    this.fs.Put(file, priKey)
    this.fs.Put(file + ".pub", pubKey)
}

func (this Rsa) pkcs1En(rsa cryptobin_rsa.Rsa, bit int) {
    for _, c := range Pkcs1Ciphers {
        // 生成证书
        priKey := rsa.
            CreatePKCS1PrivateKeyWithPassword(this.pass, c).
            ToKeyString()
        pubKey := rsa.
            CreatePKCS8PublicKey().
            ToKeyString()

        file := fmt.Sprintf("./runtime/key/key-pem/rsa/%d/rsa-pkcs1-en-%s", bit, c)

        this.fs.Put(file, priKey)
        this.fs.Put(file + ".pub", pubKey)
    }
}

func (this Rsa) pkcs8En(rsa cryptobin_rsa.Rsa, bit int) {
    for _, c := range Pkcs8Ciphers {
        for _, h := range Pkcs8Hashes {
            // 生成证书
            priKey := rsa.
                CreatePKCS8PrivateKeyWithPassword(this.pass, c, h).
                ToKeyString()
            pubKey := rsa.
                CreatePKCS8PublicKey().
                ToKeyString()

            file := fmt.Sprintf("./runtime/key/key-pem/rsa/%d/rsa-pkcs8-en-%s-%s", bit, c, h)

            this.fs.Put(file, priKey)
            this.fs.Put(file + ".pub", pubKey)
        }
    }

    for _, c2 := range Pkcs8PbeCiphers {
        // 生成证书
        priKey := rsa.
            CreatePKCS8PrivateKeyWithPassword(this.pass, c2).
            ToKeyString()
        pubKey := rsa.
            CreatePKCS8PublicKey().
            ToKeyString()

        file := fmt.Sprintf("./runtime/key/key-pem/rsa/%d/rsa-pkcs8-pbe-en-%s", bit, c2)

        this.fs.Put(file, priKey)
        this.fs.Put(file + ".pub", pubKey)
    }

}
