package morse

import "testing"

func TestLooksLikeMorse(t *testing.T) {
    if !LooksLikeMorse("- .... . .-..") {
        t.Error("fail 1")
    }
    if LooksLikeMorse("one one one...") {
        t.Error("fail 2")
    }
    if LooksLikeMorse("") {
        t.Error("fail 3")
    }
}

func TestDecodeBrokenITU(t *testing.T) {
    _, err := DecodeITU("-- ?.. ...")
    if err == nil {
        t.Error("expected error")
    }
}
