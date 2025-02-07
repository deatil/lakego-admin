package morse

import "testing"

func Test_LooksLikeMorse(t *testing.T) {
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

func Test_DecodeBrokenITU(t *testing.T) {
    _, err := ITUEncoding.DecodeString("-- ?.. ...")
    if err == nil {
        t.Error("expected error")
    }
}

func Test_EncodeToString(t *testing.T) {
    in := []byte("test:date")

    encoded := ITUEncoding.EncodeToString(in)
    if len(encoded) == 0 {
        t.Error("EncodeToString fail")
    }

    decoded, err := ITUEncoding.DecodeString(encoded)
    if err != nil {
        t.Error("DecodeString fail")
    }

    if string(decoded) != string(in) {
        t.Errorf("DecodeString, got %s, want %s", string(decoded), string(in))
    }
}
