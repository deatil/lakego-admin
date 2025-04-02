package hash_composition

import (
    "fmt"
    "hash"
    "testing"
    "encoding/hex"
    "crypto/sha256"
    "crypto/sha512"
)

func Test_Hash256(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New(sha256.New, sha256.New)
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }

    check := "2d83eef54696c60dfc3dd8913112bfa0e5625816ce98015415847fbfa639ef28"
    res := fmt.Sprintf("%x", dst)
    if res != check {
        t.Errorf("Hash error, got %s, want %s", res, check)
    }
}

func Test_Hash512(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New(sha512.New, sha512.New)
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }

    check := "ebf7ad4357f5066d23b19d63b67d24c2f24279685dd47ae5fa36ab9f85bb05ab3b9d2b3b7b8dccb2644b6b376822027f6cc27c8fd6c430957c8d20b112233f8d"
    res := fmt.Sprintf("%x", dst)
    if res != check {
        t.Errorf("Hash error, got %s, want %s", res, check)
    }
}

type testHash struct {
    Sha1 func() hash.Hash
    Sha2 func() hash.Hash
    MsgBytes []byte
    MD string
}

var testCases = []testHash{
    {
        Sha1:     sha256.New,
        Sha2:     sha256.New,
        MsgBytes: []byte(`test-datatest-datatest-datatest-datatest-data`),
        MD:       `e6efa585c2feca0df7350c9e889b6881012a0540d72a3d29bd742370e2c681d0`,
    },
    {
        Sha1:     sha512.New384,
        Sha2:     sha512.New384,
        MsgBytes: []byte(`test-datatest-datatest-datatest-datatest-data`),
        MD:       `486d463b3ef910975fbf9944803d59e2fa49554c09f49c54e4d45741cf215e7b1f201245499e958500161ea862810e00`,
    },
    {
        Sha1:     sha512.New,
        Sha2:     sha512.New,
        MsgBytes: []byte(`test-datatest-datatest-datatest-datatest-data`),
        MD:       `0bf6edcacbd2c5adac6c111d24c43e18f7e03c0cc47499d9b3312a1916fdd13cae75d86a6a7c2ffc48423e79fd21bb91ea12bb68e065a8b8bd186530608fdd8a`,
    },
}

func Test_Hash_Check(t *testing.T) {
    var dst []byte

    for _, tc := range testCases {
        h := New(tc.Sha1, tc.Sha2)
        h.Write(tc.MsgBytes)
        dst = h.Sum(dst[:0])

        dString := hex.EncodeToString(dst)

        if dString != tc.MD {
            t.Errorf("hash failed. got : %s, want: %s", dString, tc.MD)
            return
        }
    }
}

func Test_Sum(t *testing.T) {
    for _, tc := range testCases {
        dst := Sum(tc.Sha1, tc.Sha2, tc.MsgBytes)

        dString := hex.EncodeToString(dst[:])

        if dString != tc.MD {
            t.Errorf("hash failed. got : %s, want: %s", dString, tc.MD)
            return
        }
    }
}
