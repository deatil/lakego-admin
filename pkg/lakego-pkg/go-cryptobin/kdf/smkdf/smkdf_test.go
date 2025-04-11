package smkdf

import (
    "fmt"
    "hash"
    "testing"
    "math/big"

    "github.com/deatil/go-cryptobin/hash/sm3"
)

func Test_Check(t *testing.T) {
    type args struct {
        md  func() hash.Hash
        z   []byte
        len int
    }

    tests := []struct {
        name string
        args args
        want string
    }{
        {"sm3 case 1", args{sm3.New, []byte("cryptobin-test"), 16}, "a053a49125ebfe8c0b557fd8a24bb14d"},
        {"sm3 case 2", args{sm3.New, []byte("cryptobin-test"), 32}, "a053a49125ebfe8c0b557fd8a24bb14d690199de297d73191a34163829199a5b"},
        {"sm3 case 3", args{sm3.New, []byte("cryptobin-test"), 48}, "a053a49125ebfe8c0b557fd8a24bb14d690199de297d73191a34163829199a5b369ed82fde8772fd0fc5f6e3e584d72e"},
        {"sm3 case 4", args{sm3.New, []byte("feaabc31a1eda4f7aa2d212baee0bb412074914bbb06d5e87d332ed43308b21a9c4644131924b58601a780d2a57d233ac74118c3af9cd94fb1e6949ef533406ee98777397a6a6421343f9e4858fbb65d7bf516c576f25a9338be013ef8159f81"), 48}, "e9c3c4c0d0011bd517c76e330d660b625704b4338176e9f6320de620360e386b1c9ecd7d91565417cf51bb53da01a457"},
        {"sm3 case 5", args{sm3.New, []byte("feaabc31a1eda4f7aa2d212baee0bb412074914bbb06d5e87d332ed43308b21a9c4644131924b58601a780d2a57d233ac74118c3af9cd94fb1e6949ef533406ee98777397a6a6421343f9e4858fbb65d7bf516c576f25a9338be013ef8159f81"), 96}, "e9c3c4c0d0011bd517c76e330d660b625704b4338176e9f6320de620360e386b1c9ecd7d91565417cf51bb53da01a457f2679cd9407964ef77a45000b892e92a5f1916d6515db2439066f25deba6409e29eecc742621c769d1bb2e35ddc624de"},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := Key(tt.args.md, tt.args.z, tt.args.len)
            if fmt.Sprintf("%x", got) != tt.want {
                t.Errorf("Key(%v) = %x, want %s", tt.name, got, tt.want)
            }
        })
    }
}

func Test_KdfOldCase(t *testing.T) {
    x2, _ := new(big.Int).SetString("64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE", 16)
    y2, _ := new(big.Int).SetString("58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78", 16)

    expected := "006e30dae231b071dfad8aa379e90264491603"

    result := Key(sm3.New, append(x2.Bytes(), y2.Bytes()...), 19)

    if fmt.Sprintf("%x", result) != expected {
        t.Fatalf("got %x, want %s", result, expected)
    }
}

func Benchmark_Kdf(b *testing.B) {
    tests := []struct {
        zLen int
        kLen int
    }{
        {32, 32},
        {32, 64},
        {32, 128},
        {64, 32},
        {64, 64},
        {64, 128},
        {440, 32},
    }

    sm3Hash := sm3.New
    z := make([]byte, 512)
    for _, tt := range tests {
        b.Run(fmt.Sprintf("zLen=%v-kLen=%v", tt.zLen, tt.kLen), func(b *testing.B) {
            b.ReportAllocs()
            b.ResetTimer()
            for i := 0; i < b.N; i++ {
                Key(sm3Hash, z[:tt.zLen], tt.kLen)
            }
        })
    }
}
