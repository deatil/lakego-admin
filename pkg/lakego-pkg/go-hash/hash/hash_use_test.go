package hash

import (
    "fmt"
    "hash"
    "testing"
    "crypto/md5"
)

type testHash struct {}

// 编码
func (this testHash) Sum(data []byte, in []byte, cfg ...map[string]any) ([]byte, error) {
    h := md5.New()
    h.Write(data)

    if len(cfg) > 0 {
        if cfg[0]["ok"] == nil {
            return nil, fmt.Errorf("cfg key 'ok' not exists.")
        }
    } else {
        return nil, fmt.Errorf("cfg not empty.")
    }

    return h.Sum(in), nil
}

// 解码
func (this testHash) New(cfg ...map[string]any) (hash.Hash, error) {
    return md5.New(), nil
}

func init() {
    UseHash.Add("TestHash", func() IHash {
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
        e := FromString(test.input).SumBy("TestHash", nil, map[string]any{
            "ok": "123",
        })

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
        e := Hashing().NewBy("TestHash").Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewUseHash_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewUseHash")
            assert(test.output, e.ToHexString(), "NewUseHash")
        })
    }
}
