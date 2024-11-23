package fsb

import (
    "fmt"
    "hash"
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

type testCopyData struct {
    d []byte
    d2 [][][]byte
}

func Test_Copy(t *testing.T) {
    data1 := &testCopyData{
        d: []byte("abcder"),
        d2: [][][]byte{
            [][]byte{
                []byte("1111111111"),
                []byte("2222222222"),
            },
            [][]byte{
                []byte("1111111112"),
                []byte("2222222223"),
            },
        },
    }

    data2 := *data1
    copy(data2.d, []byte("abcde2"))

    if fmt.Sprintf("%s", data2.d) != fmt.Sprintf("%s", data1.d) {
        t.Errorf("got %s, want %s", data2.d, data1.d)
    }

    data3 := &testCopyData{
        d2: make([][][]byte, 2),
    }
    copy(data3.d2, data1.d2)

    data3.d2[1][1] = []byte("222222222355")

    // t.Errorf("%s", string(data1.d2[1][1]))
}

func Test_Hash(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New256()
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }
}

func Test_Check(t *testing.T) {
    for _, td := range testDatas {
        t.Run(td.name, func(t *testing.T) {
            {
                msg := []byte(td.msg)

                h, err := New(td.hashbitlen)
                if err != nil {
                    t.Fatal(err)
                }

                h.Write(msg)
                dst := h.Sum(nil)

                if fmt.Sprintf("%x", dst) != td.hashed {
                    t.Errorf("New error, got %x, want %s", dst, td.hashed)
                }
            }
            {
                msg := []byte(td.msg)

                dst, err := Sum(msg, td.hashbitlen)
                if err != nil {
                    t.Fatal(err)
                }

                if fmt.Sprintf("%x", dst) != td.hashed {
                    t.Errorf("New error, got %x, want %s", dst, td.hashed)
                }
            }

            {
                msg := []byte(td.msg)

                h := td.hash()
                h.Write(msg)
                dst := h.Sum(nil)

                if fmt.Sprintf("%x", dst) != td.hashed {
                    t.Errorf("NewXX error, got %x, want %s", dst, td.hashed)
                }
            }
            {
                msg := []byte(td.msg)

                dst := td.sum(msg)

                if fmt.Sprintf("%x", dst) != td.hashed {
                    t.Errorf("New error, got %x, want %s", dst, td.hashed)
                }
            }
        })
    }
}

type testData struct {
    name string
    hashbitlen int
    msg string
    hashed string
    hash func() hash.Hash
    sum func([]byte) []byte
}

var testDatas = []testData{
    {
        name: "New160 0",
        hashbitlen: 160,
        msg: "hello",
        hashed: "6e8ce7998e4c46a4ca7c5e8f6498a5778140d14b",
        hash: New160,
        sum: func(data []byte) []byte {
            res := Sum160(data)
            return res[:]
        },
    },
    {
        name: "New160 1",
        hashbitlen: 160,
        msg: "The quick brown fox jumps over the lazy dog",
        hashed: "a25f6e24c6fb67533f0a25233ac5cc09d5793e8a",
        hash: New160,
        sum: func(data []byte) []byte {
            res := Sum160(data)
            return res[:]
        },
    },
    {
        name: "New160 2",
        hashbitlen: 160,
        msg: "tiriri tralala potompompom",
        hashed: "bfbd2f301a8ffbcfb60f3964d96d07e6569824f9",
        hash: New160,
        sum: func(data []byte) []byte {
            res := Sum160(data)
            return res[:]
        },
    },

    {
        name: "New224 0",
        hashbitlen: 224,
        msg: "hello",
        hashed: "5b04d5f3c350d00f8815f018d21a2e7289bc6993b4fa167976962537",
        hash: New224,
        sum: func(data []byte) []byte {
            res := Sum224(data)
            return res[:]
        },
    },
    {
        name: "New224 1",
        hashbitlen: 224,
        msg: "The quick brown fox jumps over the lazy dog",
        hashed: "1dd28d92cad63335fcca4c64a5e1133ccaa8c3e6083ad15591280701",
        hash: New224,
        sum: func(data []byte) []byte {
            res := Sum224(data)
            return res[:]
        },
    },
    {
        name: "New224 2",
        hashbitlen: 224,
        msg: "tiriri tralala potompompom",
        hashed: "bd9cc65169789ab20fbba27910a9f5323d0559f107eff3c55656dd23",
        hash: New224,
        sum: func(data []byte) []byte {
            res := Sum224(data)
            return res[:]
        },
    },

    {
        name: "New256 0",
        hashbitlen: 256,
        msg: "hello",
        hashed: "0f036dc3761aed2cba9de586a85976eedde6fa8f115c0190763decc02f28edbc",
        hash: New256,
        sum: func(data []byte) []byte {
            res := Sum256(data)
            return res[:]
        },
    },
    {
        name: "New256 1",
        hashbitlen: 256,
        msg: "The quick brown fox jumps over the lazy dog",
        hashed: "a0751229aac5aeba6aeb1c0533988302e5084bb11029e7bb0ada7a653491df24",
        hash: New256,
        sum: func(data []byte) []byte {
            res := Sum256(data)
            return res[:]
        },
    },
    {
        name: "New256 2",
        hashbitlen: 256,
        msg: "tiriri tralala potompompom",
        hashed: "f997ac523044618f2837407ad76bf41a194bb558cf50ea1c64b379be2f5f2b5e",
        hash: New256,
        sum: func(data []byte) []byte {
            res := Sum256(data)
            return res[:]
        },
    },

    {
        name: "New384 0",
        hashbitlen: 384,
        msg: "hello",
        hashed: "010d14a04da89df22685138b6b7795501ebdc109b6c714364126fcb46a0b570a9d714bc992455f8cf2099c8750cdb90b",
        hash: New384,
        sum: func(data []byte) []byte {
            res := Sum384(data)
            return res[:]
        },
    },
    {
        name: "New384 1",
        hashbitlen: 384,
        msg: "The quick brown fox jumps over the lazy dog",
        hashed: "4983ecfa3930e3cf61ac4c82695c01a394016b39cf22b5d6dcba447ef8cbcda46ac341ccf5835f331fed0abe73e9bf1c",
        hash: New384,
        sum: func(data []byte) []byte {
            res := Sum384(data)
            return res[:]
        },
    },
    {
        name: "New384 2",
        hashbitlen: 384,
        msg: "tiriri tralala potompompom",
        hashed: "0597e317f2a3f311db2485f0b8335607e6bcc6f918d07f6b0dc14bc044c558a9bcd0f5f346ad85bb043ff097f43f4f95",
        hash: New384,
        sum: func(data []byte) []byte {
            res := Sum384(data)
            return res[:]
        },
    },

    {
        name: "New512 0",
        hashbitlen: 512,
        msg: "hello",
        hashed: "0c6bb476d9727b90a1f063435e8d611aacdc904e9680fe585b65442f2a3ac5043a3979ff252adf6cc9d34ef0b179a90ae2f2e8789f8797bff2426c90a58fb28b",
        hash: New512,
        sum: func(data []byte) []byte {
            res := Sum512(data)
            return res[:]
        },
    },
    {
        name: "New512 1",
        hashbitlen: 512,
        msg: "The quick brown fox jumps over the lazy dog",
        hashed: "6f87b9dc051330bfb0dd7ad35c05d6a2040e9a6110b06886368934d6ae25694fd9790b1bf1086af9da4b15619609b688fa576376f136adbd3b5a51ae1a1f2158",
        hash: New512,
        sum: func(data []byte) []byte {
            res := Sum512(data)
            return res[:]
        },
    },
    {
        name: "New512 2",
        hashbitlen: 512,
        msg: "tiriri tralala potompompom",
        hashed: "7dd5255dafac0796df851d278eb70f554a539cc3dfdfe0a3d73e46df1ab51c029d3634db022fcd032ee8376ea777e34af118821fb1ff2b34b7378e517eacdc73",
        hash: New512,
        sum: func(data []byte) []byte {
            res := Sum512(data)
            return res[:]
        },
    },

}
