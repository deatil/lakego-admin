package skein512

import (
    "fmt"
    "io"
    "bytes"
    "testing"
    "encoding/hex"
)

var testVectors = []struct {
    outLen    uint64
    args      *Args
    input     []byte
    hexResult string
}{
    {
        64,
        nil,
        nil,
        "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a",
    },
    {
        64,
        nil,
        []byte{0xff},
        "71b7bce6fe6452227b9ced6014249e5bf9a9754c3ad618ccc4e0aae16b316cc8ca698d864307ed3e80b6ef1570812ac5272dc409b5a012df2a579102f340617a",
    },
    {
        64,
        nil,
        fromHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0"),
        "45863ba3be0c4dfc27e75d358496f4ac9a736a505d9313b42b2f5eada79fc17f63861e947afb1d056aa199575ad3f8c9a3cc1780b5e5fa4cae050e989876625b",
    },
    {
        32,
        nil,
        fromHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180"),
        "1a6a5ba08e74a864b5cb052cfb9b2fa128203230a4d9923a329f5427c477a4db",
    },
    {
        48,
        nil,
        fromHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180"),
        "eeaf4dc9b668c2a270b90cbd2e986c857e464b08903e5b6dda1f15736f50d1bf2b6c40a398b79c67533592efd96bd8dc",
    },
    {
        64,
        nil,
        fromHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180"),
        "91cca510c263c4ddd010530a33073309628631f308747e1bcbaa90e451cab92e5188087af4188773a332303e6667a7a210856f742139000071f48e8ba2a5adb7",
    },
    {
        64,
        nil,
        make([]byte, 1),
        "40285f433699a1d8c799b276ccf18010c9dc9d418b0e8a4ed987b44c61c01c5ccbcc0977b1d34a4d3665d20e12716df934d208fea6607f74968ed86be3c99832",
    },
    {
        64,
        nil,
        make([]byte, 4),
        "dd01c32531e8100e470c47809bd21f84307b6b8da616c46ea1bb4f85b5475916fb86c13faf651788aa17216518c724a581948b42de791596d1569ebe91648b89",
    },
    {
        64,
        nil,
        make([]byte, 8),
        "a8c37d4ed547f6ecdca7ff52ac34977e17b568d7e8f49f0bd06cd9c98ea807999b11681b3b390fe54d523bd0ea07caae6d31b226d1a7075fc3109d9859c879d8",
    },
    {
        64,
        nil,
        make([]byte, 16),
        "fc716310cf81b8990844b195dfa76521756fb0c8f2604772056be86e83ded36f2577a8d7d6e3d2112f4637016c75099e271df12ddcb3257433f91bbe970b84aa",
    },
    {
        64,
        nil,
        make([]byte, 24),
        "708b363c78f15cb39d85824ea1339897a003a792c2a0192604b389740758b3c7d2344ca8f50f493f306d8468695b18b848eac5234952e5ac4791ec88e7184c37",
    },
    {
        64,
        nil,
        make([]byte, 32),
        "49a7f0ee7caeb28e35a70c68045571ed66388a6e98939c44c632edb2ca8a1617ca950213454da463e2df5f32284363cf386a1ef13087a9f826ebb5c86deac5ec",
    },
    {
        64,
        nil,
        make([]byte, 48),
        "e5d37d8d3ddc6a9c5f0b5df9b840ebd7343d25ec20b84892bca40560395d90c7c7ab8e4b95fa2d7bd183f18d8fdffc3b1e04ee73f6e2d17e92fc9c74183a1e8f",
    },
    {
        64,
        nil,
        make([]byte, 64),
        "33f7457de06569e7cf5fd1edd50ccfe1d5f166429e75ddbe54a5b7e247030dd912f0dc5ab6012f59ce9203abd82b316df67d5c6f009a18ba84db030146da99db",
    },
    {
        64,
        nil,
        make([]byte, 96),
        "24359e4da39db5b4995087c3173bd16dc73e65ab7ec1991f7fa8a3db239397dc09c9461157d939b28fb8107a13b31a15158bd00f85433ad2aae4a1b01b25e84d",
    },
    {
        20,
        nil,
        make([]byte, 128),
        "9cc1810ddfe971cf71fed0815df862926c85ca6e",
    },
    {
        28,
        nil,
        make([]byte, 128),
        "bec6a37a9f086bb2397ae1bdf000ec5eb87ad58039f36123a27e0ef1",
    },
    {
        32,
        nil,
        make([]byte, 128),
        "2d0e2e241972df39be822a8c682105c64747faf8a10ec032881de7dc67887cc2",
    },
    {
        48,
        nil,
        make([]byte, 128),
        "e63ea4698f314ad9f8f8cbd1f336e027955f8dce78c3210af9b1f46bd328367d8e88d431071c4385cd8b50d74862c248",
    },
    {
        64,
        nil,
        make([]byte, 128),
        "fbe65b75d681b2fe354780bddf82ccf164c5cb2827f8e4e7de96235907443428957881c76ce46555e2bb9ee34f42f7a9b2e090b55d73c7a02506e17bbdffa4f2",
    },
    {
        128,
        nil,
        make([]byte, 128),
        "4fc4315337416a601574c377205ac517235dae3d39c8485ea51908ac86fb4355d85ce6bc6f2b6538d9bdb08b694f8fda4e46642aee61438428e6ee7ec1f94eadc00996f3a441aaa91c96c19167f1ab210b6c99ab3d649592166f7420a994c9bd32bccde26391b09ceb815e2a12e3df80605d7078fb1b8fcaf01b1754cc271b6e",
    },
    {
        33,
        nil,
        make([]byte, 128),
        "24394dd21fba42a1d5d2302a237fcfea345e6e45c3c7d0ea9ab9ae374c9622c310",
    },
    {
        65,
        nil,
        make([]byte, 128),
        "c77861b1fce67c93630968f21f9e3d0c24d3470ecee205ec56192f2300e43b56d3c063f6596875092a108e8ad34c420bc2f6978d4f3c2bb6e53949a50651e00e2d",
    },
    {
        129,
        nil,
        make([]byte, 128),
        "a9758015f0892c5cfe648604ba7cc487fb6acb74b8aec28dcf24a4411ccd4639b6022cca7a11f8b3ecd3e4fbe523b0f7acf03c57fd22cda28eee389567149502b2558314792b6c01eb7250e04f794dd6ca62ffecea43b229e31ab39d3b1601958547fb133b387ce986a112b6535fc58267db07bc0be619bad07fc6d3f55379b217",
    },
    {
        257,
        nil,
        make([]byte, 128),
        "9ca33be920c52d37a412174d4273c71c10ad2ff2cec2f2399e14bd05d58542af82e4e4472a9c21a9d5d35625a903c6925df188c82326b741de2b6602fa090c743fdfc0f10e0868ed78bb067cf28af3c4e043b669f67d99abdcc3c499ccb9c3718f49041c93d87796607cc7ad52df4f9286422e4ed23dc2da1a4523a158cb7d3bc7792c808d0943e12c103a6afe688e586e9f39c0ea88e1666f84063c6700f54bfe3959b5fc9116d921a0331f3a785b373eda08f5fda339b6d7e83dfe9b403e39a2204dd5658b5023ca899580d749f1770a1d5f64a3b70d048b15d90ffa7b2c22a1b2b57b8420ab9d053c907a8bf433e428f98f31eb18e89fd5450f686d8de81920",
    },
}

func fromHex(s string) []byte {
    ret, err := hex.DecodeString(s)
    if err != nil {
        panic(err)
    }
    return ret
}

func TestNew(t *testing.T) {
    for i, v := range testVectors {
        h := New(v.outLen, v.args)
        h.Write(v.input)
        sum := fmt.Sprintf("%x", h.Sum(nil))
        if sum != v.hexResult {
            t.Errorf("%d: expected %s, got %s", i, v.hexResult, sum)
        }
    }
}

func TestCopyIo(t *testing.T) {
    for i, v := range testVectors {
        h := New(v.outLen, v.args)
        r := bytes.NewReader(v.input)
        if _, err := io.Copy(h, r); err != nil {
            t.Error(err)
        }
        sum := fmt.Sprintf("%x", h.Sum(nil))
        if sum != v.hexResult {
            t.Errorf("%d: expected %s, got %s", i, v.hexResult, sum)
        }
    }
}

func TestOutputReader(t *testing.T) {
    h := New(125, nil)
    h.Write([]byte("testing output reader"))
    sum1 := h.Sum(nil)
    sum2 := make([]byte, len(sum1))
    r := h.OutputReader()
    r.Read(nil) // read no bytes
    r.Read(sum2)
    if !bytes.Equal(sum1, sum2) {
        t.Errorf("expected %x, got %x", sum1, sum2)
    }
}

func xorInPortions(key, nonce, b []byte) {
    c := NewStream(key, nonce)
    i := 1
    for {
        c.XORKeyStream(b[:i], b[:i])
        b = b[i:]
        i *= 3
        if i >= len(b) {
            c.XORKeyStream(b, b)
            break
        }
    }

}

func TestStreamKnown(t *testing.T) {
    key := []byte("key")
    nonce := []byte("nonce")
    in := make([]byte, 10)
    known := fromHex("ed036a52bbb40f471c77")

    c := NewStream(key, nonce)
    c.XORKeyStream(in, in)
    if !bytes.Equal(in, known) {
        t.Errorf("expected: %x, got %x", known, in)
    }
}

func TestNewStream(t *testing.T) {
    key := []byte("key")
    nonce := []byte("nonce")
    in := make([]byte, 3045)
    for i := range in {
        in[i] = byte(i)
    }
    // Encrypt in portions.
    xorInPortions(key, nonce, in)
    // Decrypt whole buffer.
    c := NewStream(key, nonce)
    c.XORKeyStream(in, in)
    for i, v := range in {
        if v != byte(i) {
            t.Fatalf("byte at %d: expected %x, got %x", i, byte(i), v)
        }
    }
}

var bench = NewHash(64)
var buf = make([]byte, 8<<10)

func BenchmarkHash1K(b *testing.B) {
    b.SetBytes(1024)
    for i := 0; i < b.N; i++ {
        bench.Write(buf[:1024])
    }
}

func BenchmarkHash8K(b *testing.B) {
    b.SetBytes(int64(len(buf)))
    for i := 0; i < b.N; i++ {
        bench.Write(buf)
    }
}

func BenchmarkReset(b *testing.B) {
    b.SetBytes(64)
    tmp := make([]byte, 64)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        bench.Reset()
        bench.Write(buf[:64])
        bench.Sum(tmp[0:0])
    }
}

func BenchmarkNew(b *testing.B) {
    b.SetBytes(64)
    tmp := make([]byte, 64)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        h := NewHash(64)
        h.Write(buf[:64])
        h.Sum(tmp[0:0])
    }
}

func BenchmarkNewMAC(b *testing.B) {
    b.SetBytes(64)
    tmp := make([]byte, 64)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        h := NewMAC(64, []byte("key"))
        h.Write(buf[:64])
        h.Sum(tmp[0:0])
    }
}

func BenchmarkStream(b *testing.B) {
    s := NewStream(buf[:BlockSize], buf[:BlockSize])
    out := make([]byte, BlockSize)
    b.SetBytes(BlockSize)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        s.XORKeyStream(out, out)
    }
}
