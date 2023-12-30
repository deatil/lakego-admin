package zuc

import (
    "testing"
)

func Test_NewZuc(t *testing.T) {
    key := []byte("test-passg5tyhu8")
    iv := []byte("test-p66sg5tyhu8")

    in := []byte("test-passg5tyhu8test-passg5tyhu8test-passg5tyhu8test-passg5tyhu8test-passg5tyhu8test-passg5tyhu8test-passg5tyhu8test-passg5tyhu8test-passg5tyhu8test-passg5tyhu8test-passg5tyhu8test-passg5tyhu8")

    s := NewZucEncrypt(key, iv)

    out := make([]byte, len(in))
    s.Write(in, out)
    other := s.Sum(nil)

    copy(out[len(out)-len(other):], other)

    if len(out) == 0 {
        t.Error("NewZucEncrypt make error")
    }

    // ===========

    s2 := NewZucDecrypt(key, iv)

    out2 := make([]byte, len(out))
    s2.Write(out, out2)
    other2 := s2.Sum(nil)

    copy(out2[len(out2)-len(other2):], other2)

    if len(out2) == 0 {
        t.Error("NewZucDecrypt make error")
    }

    if string(out2) != string(in) {
        t.Error("Zuc Decrypt error")
    }
}
