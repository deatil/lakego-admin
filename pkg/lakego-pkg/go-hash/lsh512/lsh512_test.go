package lsh512

import (
    "strings"
    "testing"
    "encoding/hex"
)

func Test_Size224(t *testing.T) {
    Msg := "57F3F5DA1A7B291FEB6B7044D1"
    MD := "24D62573B16EEB4938A00FB0CD5319CD3A2A864E5DAB50322D106535"

    var dst []byte

    h := New224()

    msg, _ := hex.DecodeString(Msg)

    h.Reset()
    h.Write(msg)
    dst = h.Sum(dst[:0])

    dString := hex.EncodeToString(dst)

    if dString != strings.ToLower(MD) {
        t.Errorf("hash failed.\nresult: %s\nanswer: %s", dString, MD)
        return
    }
}

func Test_Size256(t *testing.T) {
    Msg := "7D3272CAEEAEDB3CD291BD2D719A31683C04D327"
    MD := "CC776D0F55C46F482F4CAEA9CA72C5C74AEE77342F9FF6B62052CB445626B623"

    var dst []byte

    h := New256()

    msg, _ := hex.DecodeString(Msg)

    h.Reset()
    h.Write(msg)
    dst = h.Sum(dst[:0])

    dString := hex.EncodeToString(dst)

    if dString != strings.ToLower(MD) {
        t.Errorf("hash failed.\nresult: %s\nanswer: %s", dString, MD)
        return
    }
}

func Test_Size384(t *testing.T) {
    Msg := "75B6078992FAA7A0A4FD3476EC0C98DF3BC0D55D5AD19197AA"
    MD := "735B0F1C984E6F8E03B84720AE7C66E537CE9E451F04A6826435948F491FA0F1C906FA55A7A0CD7A734F51BC1F0536C1"

    var dst []byte

    h := New384()

    msg, _ := hex.DecodeString(Msg)

    h.Reset()
    h.Write(msg)
    dst = h.Sum(dst[:0])

    dString := hex.EncodeToString(dst)

    if dString != strings.ToLower(MD) {
        t.Errorf("hash failed.\nresult: %s\nanswer: %s", dString, MD)
        return
    }
}

func Test_Size512(t *testing.T) {
    Msg := "78AECC1F4DBF27AC146780EEA8DCC56B858163329665B677480CC47D"
    MD := "1074CFC160290EF5B9E98BA729817FE58BFE3CB699CAFE2AABAF28759E2D82869F148104330C8F02BE2A4BCB90E9C9630E9CC5685250E8115EC06323B1E21C54"

    var dst []byte

    h := New()

    msg, _ := hex.DecodeString(Msg)

    h.Reset()
    h.Write(msg)
    dst = h.Sum(dst[:0])

    dString := hex.EncodeToString(dst)

    if dString != strings.ToLower(MD) {
        t.Errorf("hash failed.\nresult: %s\nanswer: %s", dString, MD)
        return
    }
}
