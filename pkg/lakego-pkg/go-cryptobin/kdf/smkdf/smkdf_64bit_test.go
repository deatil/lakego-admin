//go:build amd64 || amd64p32 || arm64 || loong64 || mips64le || ppc64le || riscv64
// +build amd64 amd64p32 arm64 loong64 mips64le ppc64le riscv64

package smkdf

import (
    "testing"

    "github.com/deatil/go-cryptobin/hash/sm3"
)

func Test_64bit_Fail(t *testing.T) {
    defer func() {
        if err := recover(); err == nil {
            t.Error("should throw panic")
        }
    }()

    _ = Key(sm3.New, []byte("go-cryptobin-test"), 1 << 38)
}
