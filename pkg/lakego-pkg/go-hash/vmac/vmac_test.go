package vmac

import (
    "fmt"
    "strings"
    "testing"
)

var key = []byte("abcdefghijklmnop")
var nonce = []byte("bcdefghi")

type vmacTest struct {
    size    int
    message string
    sum     string
}

// Tests from http://fastcrypto.org/vmac/draft-krovetz-vmac-01.txt
var vmacTests = []vmacTest{
    {8, "", "2576BE1C56D8B81B"},
    {16, "", "472766C70F74ED23481D6D7DE4E80DAC"},
    {8, "abc", "2D376CF5B1813CE5"},
    {16, "abc", "4EE815A06A1D71EDD36FC75D51188A42"},
    {8, strings.Repeat("abc", 16), "E8421F61D573D298"},
    {16, strings.Repeat("abc", 16), "09F2C80C8E1007A0C12FAE19FE4504AE"},
    {8, strings.Repeat("abc", 100), "4492DF6C5CAC1BBE"},
    {16, strings.Repeat("abc", 100), "66438817154850C61D8A412164803BCB"},
    {8, strings.Repeat("abc", 1000000), "09BA597DD7601113"},
    {16, strings.Repeat("abc", 1000000), "2B6B02288FFC461B75485DE893C629DC"},
}

func TestVmac(t *testing.T) {
    for i, test := range vmacTests {
        h, err := New(key, nonce, test.size)
        if err != nil {
            t.Errorf("Test %d: New(%x, %x, %d) failed with error=%s\n", i, key, nonce, test.size, err)
            continue
        }

        // Iterate twice to test Reset()
        for j := 0; j < 2; j++ {
            n, err := h.Write([]byte(test.message))
            if n != len(test.message) || err != nil {
                t.Errorf("Test %d.%d: Write('abc' * %d) failed with n=%d and error=%s\n", i, j, len(test.message)/3, n, err)
                continue
            }

            // Sum should be idempotent
            for k := 0; k < 2; k++ {
                sum := fmt.Sprintf("%X", h.Sum(nil))
                if sum != test.sum {
                    t.Errorf("Test %d.%d.%d: Sum() returned %s, expected %s\n", i, j, k, sum, test.sum)
                }
            }

            h.Reset()
        }
    }
}

func BenchmarkVmac(b *testing.B) {
    b.StopTimer()
    test := vmacTests[7]
    h, _ := New(key, nonce, test.size)
    h.Write([]byte(test.message))
    b.StartTimer()
    for i := 0; i < b.N; i++ {
        h.Sum(nil)
    }
}
