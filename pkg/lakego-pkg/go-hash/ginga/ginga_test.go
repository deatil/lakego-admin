package ginga

import (
    "bytes"
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

type testData struct {
    msg []byte
    md []byte
}

func Test_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("35568c26aaef838bea35432cb9e0f7d7f6eb6e5006f32fd8f54fe9f1ee1e07f7"),
        },
        {
           fromHex("cc"),
           fromHex("7d3ce743bddac91036a49dc547f9b6d7a120c4b232b94a212b54f7bc63f0bf0c"),
        },
        {
           fromHex("1f877c"),
           fromHex("1d65fd2d46f656d63747779f78897aeacacb03cb294650e624d6e563c1909ae3"),
        },
        {
           fromHex("c6f50bb74e29"),
           fromHex("8643a4e3400162652b875f1fd06f8f3dce0bc94a7bd17f0665434c5c77f39c32"),
        },
        {
           fromHex("eed7422227613b6f53c9"),
           fromHex("64281b90418048d53aa916ed443d97383fb2af5dc05cb54b47cd3f08ba885cbd"),
        },
        {
           fromHex("3c5871cd619c69a63b540eb5a625"),
           fromHex("abf144a0ff0126e0823c316e83838acad8b6301b5f8eec7ff6fa873107205895"),
        },
        {
           fromHex("c8f2b693bd0d75ef99caebdc22adf4088a95a3542f637203e283bbc3268780e787d68d28cc3897452f6a22aa8573ccebf245972a"),
           fromHex("f377aac3eb911462b06ac056157d42d0eeeb397d4dd2d96c23e8d5ccc781618c"),
        },
        {
           fromHex("90078999fd3c35b8afbf4066cbde335891365f0fc75c1286cdd88fa51fab94f9b8def7c9ac582a5dbcd95817afb7d1b48f63704e19c2baa4df347f48d4a6d603013c23f1e9611d595ebac37c"),
           fromHex("316f1226f62c6dd7e52f156a8264033cb7aff3dbd8409f500ede8e8007a54fcc"),
        },
        {
           fromHex("3c9b46450c0f2cae8e3823f8bdb4277f31b744ce2eb17054bddc6dff36af7f49fb8a2320cc3bdf8e0a2ea29ad3a55de1165d219adeddb5175253e2d1489e9b6fdd02e2c3d3a4b54d60e3a47334c37913c5695378a669e9b72dec32af5434f93f46176ebf044c4784467c700470d0c0b40c8a088c815816"),
           fromHex("f0dff940f9745db647bbe1b528a288c0995154e4cb0a49ca6d90ac05b9050e39"),
        },
        {
           fromHex("83599d93f5561e821bd01a472386bc2ff4efbd4aed60d5821e84aae74d8071029810f5e286f8f17651cd27da07b1eb4382f754cd1c95268783ad09220f5502840370d494beb17124220f6afce91ec8a0f55231f9652433e5ce3489b727716cf4aeba7dcda20cd29aa9a859201253f948dd94395aba9e3852bd1d60dda7ae5dc045b283da006e1cbad83cc13292a315db5553305c628dd091146597"),
           fromHex("ed9f1982410923b698b5aa6b9ef5aea31e44ca49a2394db9508df2ccfac3bd77"),
        },
    }

    h := New()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

