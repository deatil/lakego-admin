### DH 使用文档

* DH 使用
~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-cryptobin/dh/dh"
)

func main() {
    // dh 验证
    // 可用 [NewDH3526_2048() | NewDH3526_3072() | NewDH3526_4096()]
    dh1 := dh.NewDH3526_4096()
    dh1pri, dh1pub, _ := dh1.GenerateKey(nil)

    dh2 := dh.NewDH3526_4096()
    dh2pri, dh2pub, _ := dh2.GenerateKey(nil)

    dh1secret := dh1.ComputeSecret(dh1pri, dh2pub)
    dh2secret := dh2.ComputeSecret(dh2pri, dh1pub)

    dhStatus := false
    if string(dh1secret.Bytes()) == string(dh2secret.Bytes()) {
        dhStatus = true
    }

    fmt.Println("生成的密钥是否相同结果: ", dhStatus)
}
~~~

* ecdh 使用
~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-cryptobin/dh/ecdh"
)

func main() {
    // ecdh 验证
    // 可选 [P521 | P384 | P256 | P224]
    dh1 := ecdh.New("P384")
    dh1pri, dh1pub, _ := dh1.GenerateKey(nil)

    dh2 := ecdh.New("P384")
    dh2pri, dh2pub, _ := dh2.GenerateKey(nil)

    dh1secret := dh1.ComputeSecret(dh1pri, dh2pub)
    dh2secret := dh2.ComputeSecret(dh2pri, dh1pub)

    dhStatus := false
    if string(dh1secret) == string(dh2secret) {
        dhStatus = true
    }

    fmt.Println("生成的密钥是否相同结果: ", dhStatus)
}
~~~

* curve25519 使用
~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-cryptobin/dh/curve25519"
)

func main() {
    // curve25519 验证
    dh1 := curve25519.New()
    dh1pri, dh1pub, _ := dh1.GenerateKey(nil)

    dh2 := curve25519.New()
    dh2pri, dh2pub, _ := dh2.GenerateKey(nil)

    dh1secret := dh1.ComputeSecret(dh1pri, dh2pub)
    dh2secret := dh2.ComputeSecret(dh2pri, dh1pub)

    dhStatus := false
    if string(dh1secret) == string(dh2secret) {
        dhStatus = true
    }

    fmt.Println("生成的密钥是否相同结果: ", dhStatus)
}
~~~
