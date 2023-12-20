package zuc

import (
    "testing"
)

func Test_Zuc256(t *testing.T) {
    key := []byte("test-passg5tyhu8test-passg5tyhu8")
    iv := []byte("test-passg5tyhu8test-pa")

    in := []byte("test-passg5tyhu8test-passg5tyhu8test-passg5tyhu8test-passg5tyhu8")

    s := NewZuc256State(key, iv)

    out := make([]byte, len(in))
    s.Encrypt(out, in)

    if len(out) == 0 {
        t.Error("Zuc make error")
    }

    // ===========

    s2 := NewZuc256State(key, iv)

    out2 := make([]byte, len(in))
    s2.Encrypt(out2, out)

    if len(out) == 0 {
        t.Error("Zuc make 2 error")
    }

    if string(out2) != string(in) {
        t.Error("Zuc Decrypt error")
    }
}
