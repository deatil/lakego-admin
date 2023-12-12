package whirlpool_test

import (
    "fmt"
    "testing"

    "github.com/deatil/go-hash/whirlpool"
)

func Test_Check(t *testing.T) {
    hashed := "717163DE24809FFCF7FF6D5ABA72B8D67C2129721953C252A4DDFB107614BE857CBD76A9D5927DE14633D6BDC9DDF335160B919DB5C6F12CB2E6549181912EEF"
    data := "abcdefghij"

    h := whirlpool.New()
    h.Write([]byte(data))

    s := fmt.Sprintf("%X", h.Sum(nil))
    if s != hashed {
        t.Fatalf("got %s, want %s", s, hashed)
    }
}

func Test_SumCheck(t *testing.T) {
    hashed := "717163DE24809FFCF7FF6D5ABA72B8D67C2129721953C252A4DDFB107614BE857CBD76A9D5927DE14633D6BDC9DDF335160B919DB5C6F12CB2E6549181912EEF"
    data := "abcdefghij"

    s := fmt.Sprintf("%X", whirlpool.Sum([]byte(data)))
    if s != hashed {
        t.Fatalf("Sum got %s, want %s", s, hashed)
    }
}
