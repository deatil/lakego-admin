package key

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_dh "github.com/deatil/go-cryptobin/cryptobin/dh/dh"
)

func NewDH() DH {
    fs := filesystem.New()

    path := "./runtime/key/key-pem/dh/dh"

    return DH{fs, "123", path, "dh"}
}

var groups = []string{
    "P1001",
    "P1002",
    "P1536",
    "P2048",
    "P3072",
    "P4096",
    "P6144",
    "P8192",
    "Rand",
}

type DH struct {
    fs   *filesystem.Filesystem
    pass string
    path string
    name string
}

func (this DH) Make() {
    for _, group := range groups {
        obj := cryptobin_dh.New()

        if group == "Rand" {
            obj = obj.SetRandGroup(int64(1024))
        } else {
            obj = obj.SetGroup(group)
        }

        obj = obj.GenerateKey()

        this.pkcs8(obj, group)
        this.pkcs8En(obj, group)
    }
}

func (this DH) pkcs8(obj cryptobin_dh.Dh, dir string) {
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

func (this DH) pkcs8En(obj cryptobin_dh.Dh, dir string) {
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
