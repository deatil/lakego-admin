package blake256

import (
    "fmt"
    "hash"
    "bytes"
    "testing"
    "encoding/hex"
)

func fromHex(s string) string {
    h, _ := hex.DecodeString(s)
    return string(h)
}

func Test_256C(t *testing.T) {
    // Test as in C program.
    var hashes = [][]byte{
        {
            0x0C, 0xE8, 0xD4, 0xEF, 0x4D, 0xD7, 0xCD, 0x8D,
            0x62, 0xDF, 0xDE, 0xD9, 0xD4, 0xED, 0xB0, 0xA7,
            0x74, 0xAE, 0x6A, 0x41, 0x92, 0x9A, 0x74, 0xDA,
            0x23, 0x10, 0x9E, 0x8F, 0x11, 0x13, 0x9C, 0x87,
        },
        {
            0xD4, 0x19, 0xBA, 0xD3, 0x2D, 0x50, 0x4F, 0xB7,
            0xD4, 0x4D, 0x46, 0x0C, 0x42, 0xC5, 0x59, 0x3F,
            0xE5, 0x44, 0xFA, 0x4C, 0x13, 0x5D, 0xEC, 0x31,
            0xE2, 0x1B, 0xD9, 0xAB, 0xDC, 0xC2, 0x2D, 0x41,
        },
    }
    data := make([]byte, 72)

    h := New()
    h.Write(data[:1])
    sum := h.Sum(nil)
    if !bytes.Equal(hashes[0], sum) {
        t.Errorf("0: expected %X, got %X", hashes[0], sum)
    }

    // Try to continue hashing.
    h.Write(data[1:])
    sum = h.Sum(nil)
    if !bytes.Equal(hashes[1], sum) {
        t.Errorf("1(1): expected %X, got %X", hashes[1], sum)
    }

    // Try with reset.
    h.Reset()
    h.Write(data)
    sum = h.Sum(nil)
    if !bytes.Equal(hashes[1], sum) {
        t.Errorf("1(2): expected %X, got %X", hashes[1], sum)
    }
}

type blakeVector struct {
    out, in string
}

var vectors256 = []blakeVector{
    {"7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7",
        "The quick brown fox jumps over the lazy dog"},
    {"07663e00cf96fbc136cf7b1ee099c95346ba3920893d18cc8851f22ee2e36aa6",
        "BLAKE"},
    {"716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a",
        ""},
    {"18a393b4e62b1887a2edf79a5c5a5464daf5bbb976f4007bea16a73e4c1e198e",
        "'BLAKE wins SHA-3! Hooray!!!' (I have time machine)"},
    {"fd7282ecc105ef201bb94663fc413db1b7696414682090015f17e309b835f1c2",
        "Go"},
    {"1e75db2a709081f853c2229b65fd1558540aa5e7bd17b04b9a4b31989effa711",
        "HELP! I'm trapped in hash!"},
    {"4181475cb0c22d58ae847e368e91b4669ea2d84bcd55dbf01fe24bae6571dd08",
        `Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur. Donec ut libero sed arcu vehicula ultricies a non tortor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ut gravida lorem. Ut turpis felis, pulvinar a semper sed, adipiscing id dolor. Pellentesque auctor nisi id magna consequat sagittis. Curabitur dapibus enim sit amet elit pharetra tincidunt feugiat nisl imperdiet. Ut convallis libero in urna ultrices accumsan. Donec sed odio eros. Donec viverra mi quis quam pulvinar at malesuada arcu rhoncus. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. In rutrum accumsan ultricies. Mauris vitae nisi at sem facilisis semper ac in est.`,
    },
    {"af95fffc7768821b1e08866a2f9f66916762bfc9d71c4acb5fd515f31fd6785a", // test with one padding byte
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congu",
    },

    {"258020d5b04a814f2b72c1c661e1f5a5c395d9799e5eee8b8519cf7300e90cb1",
        fromHex("3c5871cd619c69a63b540eb5a625")},
    {"75d95470d72557d86cad03967552b34d925f6e5e9be7e887b57d6d444ec93d70",
        fromHex("6892540f964c8c74bd2db02c0ad884510cb38afd4438af31fc912756f3efec6b32b58ebc38fc2a6b913596a8")},
    {"6d40d076120ae4a5a5301fbc2fc5764f83fcfcfbb608738527b769108a33bb41",
        fromHex("08461f006cff4cc64b752c957287e5a0faabc05c9bff89d23fd902d324c79903b48fcb8f8f4b01f3e4ddb483593d25f000386698f5ade7faade9615fdc50d32785ea51d49894e45baa3dc707e224688c6408b68b11")},
}

var vectors224 = []blakeVector{
    {"c8e92d7088ef87c1530aee2ad44dc720cc10589cc2ec58f95a15e51b",
        "The quick brown fox jumps over the lazy dog"},
    {"cfb6848add73e1cb47994c4765df33b8f973702705a30a71fe4747a3",
        "BLAKE"},
    {"7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed",
        ""},
    {"dde9e442003c24495db607b17e07ec1f67396cc1907642a09a96594e",
        "Go"},
    {"9f655b0a92d4155754fa35e055ce7c5e18eb56347081ea1e5158e751",
        "Buffalo buffalo Buffalo buffalo buffalo buffalo Buffalo buffalo"},

    {"4239b4afa926f2269b117059dc0310033c9c85acea1a031f97cd4e2a",
        fromHex("1f877c")},
    {"dced7bb2e882d4586e867e49df28e445dcdd029ccd202b21ce0afb51",
        fromHex("512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542")},
    {"09b07523037d6c00bb6aa44f3c6748739275cda0f0d0387517c769db",
        fromHex("13bd2811f6ed2b6f04ff3895aceed7bef8dcd45eb121791bc194a0f806206bffc3b9281c2b308b1a729ce008119dd3066e9378acdcc50a98a82e20738800b6cddbe5fe9694ad6d")},
}

func newTestVectors(t *testing.T, hashfunc func() hash.Hash, vectors []blakeVector) {
    for i, v := range vectors {
        h := hashfunc()
        h.Write([]byte(v.in))
        res := fmt.Sprintf("%x", h.Sum(nil))
        if res != v.out {
            t.Errorf("%d: expected %q, got %q", i, v.out, res)
        }
    }
}

func Test_New(t *testing.T) {
    newTestVectors(t, New, vectors256)
}

func Test_New224(t *testing.T) {
    newTestVectors(t, New224, vectors224)
}

func Test_Sum(t *testing.T) {
    for i, v := range vectors256 {
        res := fmt.Sprintf("%x", Sum([]byte(v.in)))
        if res != v.out {
            t.Errorf("%d: expected %q, got %q", i, v.out, res)
        }
    }
}

func Test_Sum224(t *testing.T) {
    for i, v := range vectors224 {
        res := fmt.Sprintf("%x", Sum224([]byte(v.in)))
        if res != v.out {
            t.Errorf("%d: expected %q, got %q", i, v.out, res)
        }
    }
}

var vectors256salt = []struct{ out, in, salt string }{
    {"561d6d0cfa3d31d5eedaf2d575f3942539b03522befc2a1196ba0e51af8992a8",
        "",
        "1234567890123456"},
    {"88cc11889bbbee42095337fe2153c591971f94fbf8fe540d3c7e9f1700ab2d0c",
        "It's so salty out there!",
        "SALTsaltSaltSALT"},
}

func Test_Salt(t *testing.T) {
    for i, v := range vectors256salt {
        h := NewWithSalt([]byte(v.salt))
        h.Write([]byte(v.in))
        res := fmt.Sprintf("%x", h.Sum(nil))
        if res != v.out {
            t.Errorf("%d: expected %q, got %q", i, v.out, res)
        }
    }

    // Check that passing bad salt length panics.
    defer func() {
        if err := recover(); err == nil {
            t.Errorf("expected panic for bad salt length")
        }
    }()

    NewWithSalt([]byte{1, 2, 3, 4, 5, 6, 7, 8})
}

var vectors224salt = []struct{ out, in, salt string }{
    {"e28df478e7e4bc7ab73111f3352f3e9ac10200fa1f00f6717301c019",
        "",
        "1234567890123456"},
    {"288b80c5de334c0d3283c25ccd691ccee5c842b62ecc49e3dce8edcb",
        "It's so salty out there!",
        "SALTsaltSaltSALT"},
}

func Test_Salt224(t *testing.T) {
    for i, v := range vectors224salt {
        h := New224WithSalt([]byte(v.salt))
        h.Write([]byte(v.in))
        res := fmt.Sprintf("%x", h.Sum(nil))
        if res != v.out {
            t.Errorf("%d: expected %q, got %q", i, v.out, res)
        }
    }

    // Check that passing bad salt length panics.
    defer func() {
        if err := recover(); err == nil {
            t.Errorf("expected panic for bad salt length")
        }
    }()

    New224WithSalt([]byte{1, 2, 3, 4, 5, 6, 7, 8, 7, 8})
}

func Test_TwoWrites(t *testing.T) {
    b := make([]byte, 65)
    for i := range b {
        b[i] = byte(i)
    }
    h1 := New()
    h1.Write(b[:1])
    h1.Write(b[1:])
    sum1 := h1.Sum(nil)

    h2 := New()
    h2.Write(b)
    sum2 := h2.Sum(nil)

    if !bytes.Equal(sum1, sum2) {
        t.Errorf("Result of two writes differs from a single write with the same bytes")
    }
}

var buf_in = make([]byte, 8<<10)
var buf_out = make([]byte, 32)

func Benchmark1K(b *testing.B) {
    b.SetBytes(1024)
    for i := 0; i < b.N; i++ {
        var bench = New()
        bench.Write(buf_in[:1024])
        _ = bench.Sum(buf_out[0:0])
    }
}

func Benchmark8K(b *testing.B) {
    b.SetBytes(int64(len(buf_in)))
    for i := 0; i < b.N; i++ {
        var bench = New()
        bench.Write(buf_in)
        _ = bench.Sum(buf_out[0:0])
    }
}

func Benchmark64(b *testing.B) {
    b.SetBytes(64)
    for i := 0; i < b.N; i++ {
        var bench = New()
        bench.Write(buf_in[:64])
        _ = bench.Sum(buf_out[0:0])
    }
}

func Benchmark1KNoAlloc(b *testing.B) {
    b.SetBytes(1024)
    for i := 0; i < b.N; i++ {
        _ = Sum(buf_in[:1024])
    }
}

func Benchmark8KNoAlloc(b *testing.B) {
    b.SetBytes(int64(len(buf_in)))
    for i := 0; i < b.N; i++ {
        _ = Sum(buf_in)
    }
}

func Benchmark64NoAlloc(b *testing.B) {
    b.SetBytes(64)
    for i := 0; i < b.N; i++ {
        _ = Sum(buf_in[:64])
    }
}
