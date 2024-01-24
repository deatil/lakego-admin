package zero

import (
    "fmt"
    "testing"
)

func Test_Reader(t *testing.T) {
    check := []byte{0, 0, 0, 0, 0, 0}
    str   := make([]byte, 6)

    res, err := Reader.Read(str)
    if err != nil {
        t.Fatal(err)
    }

    if res != len(check) {
        t.Errorf("Read error, got %d, want %d", res, len(check))
    }

    if fmt.Sprintf("%x", str) != fmt.Sprintf("%x", check) {
        t.Errorf("Read data error, got %x, want %x", str, check)
    }

}
