package hash

import (
    "testing"
)

func Test_MD2(t *testing.T) {
    eq := assertT(t)
    err := assertErrorT(t)

    msg := "abcdefghijklmnopqrstuvwxyz"
    md  := "4e8ddff3650292ab5a4108c3aa47940b"

    t.Run("Sum", func(t *testing.T) {
        e := FromString(msg).MD2()

        err(e.Error, "Sum")
        eq(e.ToHexString(), md, "Sum")
    })

    t.Run("New", func(t *testing.T) {
        e := Hashing().
            NewMD2().
            Write([]byte(msg)).
            Sum(nil)

        err(e.Error, "New")
        eq(e.ToHexString(), md, "New")
    })
}
