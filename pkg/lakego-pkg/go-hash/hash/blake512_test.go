package hash

import (
    "testing"
)

func Test_Blake512(t *testing.T) {
    eq := assertT(t)
    err := assertErrorT(t)

    msg := fromHex("c6f50bb74e29")
    md  := "b6e8a7380df1f007d7c271e7255bbca7714f25029ac1fd6fe92ef74cbcd9e99c112f8ae1a45ccb566ce19d9678a122c612beff5f8eeeee3f3f402fd2781182d4"

    t.Run("Sum", func(t *testing.T) {
        e := FromBytes(msg).Blake512()

        err(e.Error, "Sum")
        eq(e.ToHexString(), md, "Sum")
    })

    t.Run("New", func(t *testing.T) {
        e := Hashing().
            NewBlake512().
            Write(msg).
            Sum(nil)

        err(e.Error, "New")
        eq(e.ToHexString(), md, "New")
    })
}

func Test_Blake384(t *testing.T) {
    eq := assertT(t)
    err := assertErrorT(t)

    msg := fromHex("c6f50bb74e29")
    md  := "5ddb50068ca430bffae7e5a8bbcb2c59171743cce027c0ea937fa2b511848192af2aca98ead30b0850b4d2d1542decdb"

    t.Run("Sum", func(t *testing.T) {
        e := FromBytes(msg).Blake384()

        err(e.Error, "Sum")
        eq(e.ToHexString(), md, "Sum")
    })

    t.Run("New", func(t *testing.T) {
        e := Hashing().
            NewBlake384().
            Write(msg).
            Sum(nil)

        err(e.Error, "New")
        eq(e.ToHexString(), md, "New")
    })
}
