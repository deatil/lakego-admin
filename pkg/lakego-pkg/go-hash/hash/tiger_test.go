package hash

import (
    "fmt"
    "testing"
)

func Test_Tiger(t *testing.T) {
    in := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    check := "8dcea680a17583ee502ba38a3c368651890ffbccdc49a8cc"

    res := FromString(in).Tiger().ToBytes()

    if fmt.Sprintf("%x", res) != check {
        t.Errorf("Check Hash error, got %x, want %s", res, check)
    }
}

func Test_Tiger2(t *testing.T) {
    in := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    check := "ea9ab6228cee7b51b77544fca6066c8cbb5bbae6319505cd"

    res := FromString(in).Tiger2().ToBytes()

    if fmt.Sprintf("%x", res) != check {
        t.Errorf("Check Hash error, got %x, want %s", res, check)
    }
}
