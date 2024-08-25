package hash

import (
    "fmt"
    "hash"
    "testing"
    "crypto/md5"
)

type testHash struct {}

// 编码
func (this testHash) Sum(data []byte, cfg ...any) ([]byte, error) {
    if len(cfg) == 0 {
        return nil, fmt.Errorf("cfg not empty.")
    }
    if cfg[0].(string) != "ok123" {
        return nil, fmt.Errorf(`cfg not "ok123".`)
    }

    h := md5.New()
    h.Write(data)
    return h.Sum(nil), nil
}

// 解码
func (this testHash) New(cfg ...any) (hash.Hash, error) {
    if len(cfg) == 0 {
        return nil, fmt.Errorf("cfg not empty.")
    }
    if cfg[0].(string) != "ok321" {
        return nil, fmt.Errorf(`cfg not "ok321".`)
    }

    return md5.New(), nil
}

var TestHash = TypeMode.Generate()

func init() {
    UseHash.Add(TestHash, func() IHash {
        return testHash{}
    })
}

var useHashTests = []struct {
    input  string
    output string
}{
    {"sdfgsdgfsdfg123132", "f7d9f5d96d7935a47cee64ab0560843d"},
    {"dfg.;kp[jewijr0-34lsd", "808c4183cd07a8f9fdac2dc06107d0d9"},
    {"123123", "4297f44b13955235245b2497399d7a93"},
}

func Test_UseHash(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range useHashTests {
        e := FromString(test.input).
            SumBy(TestHash, "ok123")

        t.Run(fmt.Sprintf("UseHash_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "UseHash")
            assert(test.output, e.ToHexString(), "UseHash")
        })
    }
}

func Test_NewUseHash(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range useHashTests {
        t.Run(fmt.Sprintf("NewUseHash_test_%d", index), func(t *testing.T) {
            e := Hashing().
                NewBy(TestHash, "ok321")
            err := e.Error

            if err != nil {
                assertError(err, "NewUseHash")
                return
            }

            e = e.
                Write([]byte(test.input)).
                Sum(nil)
            assert(test.output, e.ToHexString(), "NewUseHash")
        })
    }
}
