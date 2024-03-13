package xoodoo_test

import (
    "testing"

    "github.com/deatil/go-cryptobin/cipher/xoodoo/xoodoo"
)

func Test_NewXoodoo(t *testing.T) {
    newXoodoo, _ := xoodoo.NewXoodoo(xoodoo.MaxRounds, [xoodoo.StateSizeBytes]byte{})

    if len(newXoodoo.Bytes()) == 0 {
        t.Error("NewXoodoo fail")
    }

    newXoodoo.Permutation()

    if len(newXoodoo.Bytes()) == 0 {
        t.Error("after Permutation and NewXoodoo fail")
    }
}
