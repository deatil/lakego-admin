package makwa_test

import (
    "bytes"
    "testing"

    "github.com/deatil/go-hash/makwa"
)

func TestDigestMarshalText(t *testing.T) {
    d := &makwa.Digest{
        ModulusID:   modulusID,
        Hash:        hash,
        Salt:        salt,
        WorkFactor:  4096,
        PreHash:     false,
        PostHashLen: 12,
    }

    b, err := d.MarshalText()
    if err != nil {
        t.Fatal(err)
    }

    if v, want := string(b), "+RK3n5jz7gs_s211_xycDwiqW2ZkvPeqHZJfjkg_yc6g5u8JOTqxcQoI"; v != want {
        t.Errorf("Was %s, but expected %s", v, want)
    }
}

func TestDigestUnmarshalText(t *testing.T) {
    d := &makwa.Digest{}
    if err := d.UnmarshalText([]byte("+RK3n5jz7gs_s211_xycDwiqW2ZkvPeqHZJfjkg_yc6g5u8JOTqxcQoI")); err != nil {
        t.Fatal(err)
    }

    if !bytes.Equal(d.ModulusID, modulusID) {
        t.Errorf("ModulusID was %x but expected %x", d.ModulusID, modulusID)
    }

    if !bytes.Equal(d.Hash, hash) {
        t.Errorf("Hash was %x but expected %x", d.Hash, hash)
    }

    if !bytes.Equal(d.Salt, salt) {
        t.Errorf("Salt was %x but expected %x", d.Salt, salt)
    }

    if v, want := d.WorkFactor, 4096; v != want {
        t.Errorf("WorkFactor was %v, but expected %v", v, want)
    }

    if d.PreHash {
        t.Errorf("PreHash was %v, but expected false", d.PreHash)
    }

    if v, want := d.PostHashLen, 12; v != want {
        t.Errorf("PostHashLen was %v, but expected %v", v, want)
    }
}
