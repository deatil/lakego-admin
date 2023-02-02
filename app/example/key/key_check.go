package key

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_dsa "github.com/deatil/go-cryptobin/cryptobin/dsa"
    cryptobin_ecdsa "github.com/deatil/go-cryptobin/cryptobin/ecdsa"
    cryptobin_eddsa "github.com/deatil/go-cryptobin/cryptobin/eddsa"
    cryptobin_rsa "github.com/deatil/go-cryptobin/cryptobin/rsa"
    cryptobin_sm2 "github.com/deatil/go-cryptobin/cryptobin/sm2"
)

// 检测测试
func KeyCheck() {
    CheckDSA()
    CheckEcDSA()
    CheckEdDSA()
    CheckRSA()
    CheckSM2()
}

func CheckDSA() {
    pri := ReadFile("./runtime/key/key-pem/dsa/L2048N256/dsa-pkcs8")
    pub := ReadFile("./runtime/key/key-pem/dsa/L2048N256/dsa-pkcs8.pub")

    res := cryptobin_dsa.New().
        FromPKCS8PrivateKey([]byte(pri)).
        FromPKCS8PublicKey([]byte(pub)).
        CheckKeyPair()

    fmt.Println("===== dsa =====")
    fmt.Printf("check res: %#v", res)
    fmt.Println("")
}

func CheckEcDSA() {
    pri := ReadFile("./runtime/key/key-pem/ecdsa/P256/ecdsa-pkcs8")
    pub := ReadFile("./runtime/key/key-pem/ecdsa/P256/ecdsa-pkcs8.pub")

    res := cryptobin_ecdsa.New().
        FromPrivateKey([]byte(pri)).
        FromPublicKey([]byte(pub)).
        CheckKeyPair()

    fmt.Println("===== ecdsa =====")
    fmt.Printf("check res: %#v", res)
    fmt.Println("")
}

func CheckEdDSA() {
    pri := ReadFile("./runtime/key/key-pem/eddsa/eddsa-pkcs8")
    pub := ReadFile("./runtime/key/key-pem/eddsa/eddsa-pkcs8.pub")

    res := cryptobin_eddsa.New().
        FromPrivateKey([]byte(pri)).
        FromPublicKey([]byte(pub)).
        CheckKeyPair()

    fmt.Println("===== eddsa =====")
    fmt.Printf("check res: %#v", res)
    fmt.Println("")
}

func CheckRSA() {
    pri := ReadFile("./runtime/key/key-pem/rsa/2048/rsa-pkcs8")
    pub := ReadFile("./runtime/key/key-pem/rsa/2048/rsa-pkcs8.pub")

    res := cryptobin_rsa.New().
        FromPKCS8PrivateKey([]byte(pri)).
        FromPKCS8PublicKey([]byte(pub)).
        CheckKeyPair()

    fmt.Println("===== rsa =====")
    fmt.Printf("check res: %#v", res)
    fmt.Println("")
}

func CheckSM2() {
    pri := ReadFile("./runtime/key/key-pem/sm2/sm2-pkcs8")
    pub := ReadFile("./runtime/key/key-pem/sm2/sm2-pkcs8.pub")

    res := cryptobin_sm2.New().
        FromPrivateKey([]byte(pri)).
        FromPublicKey([]byte(pub)).
        CheckKeyPair()

    fmt.Println("===== sm2 =====")
    fmt.Printf("check res: %#v", res)
    fmt.Println("")
}

func ReadFile(file string) string {
    fs := filesystem.New()

    data, _ := fs.Get(file)

    return data
}
