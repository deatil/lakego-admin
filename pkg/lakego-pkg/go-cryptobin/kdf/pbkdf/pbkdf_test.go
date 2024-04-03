package pbkdf

import (
    "fmt"
    "hash"
    "bytes"
    "testing"
    "crypto/md5"
    "crypto/sha1"
)

func Test_PBKDF(t *testing.T) {
    type args struct {
        md         func() hash.Hash
        password   []byte
        salt       []byte
        iterations int
    }

    tests := []struct {
        name string
        args args
        want string
    }{
        {"pbkdf case 1", args{md5.New, []byte("test password"), []byte("test salt"), 2}, "8af38927dabe590d5dd2c2d3b251d5c3"},
        {"pbkdf case 2", args{md5.New, []byte("test password"), []byte("test salt"), 4}, "b23308de507cfdd8f85b8db296d50516"},
        {"pbkdf case 3", args{sha1.New, []byte("test password"), []byte("test salt"), 12}, "814bd97777662e630963bc59d69c76bab1e97a0a"},
        {"pbkdf case 4", args{sha1.New, []byte("test password"), []byte("test salt"), 24}, "9cd600433ad4f137f3d6e46e37e6f7be26185e55"},
        {"pbkdf case 5", args{sha1.New, []byte("test password"), []byte("test salt"), 56}, "8713b8e66dc5b34f109f96eed44965e4435700bd"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            h := tt.args.md
            hashSize := h().Size()

            got := Key(h, hashSize, 64, tt.args.salt, tt.args.password, tt.args.iterations, 3, hashSize)

            if fmt.Sprintf("%x", got) != tt.want {
                t.Errorf("Key(%v) = %x, want %s", tt.name, got, tt.want)
            }
        })
    }
}

func Test_PBKDFHandlesLeadingZeros(t *testing.T) {
    key := Key(sha1.New, 20, 64, []byte("\xf3\x7e\x05\xb5\x18\x32\x4b\x4b"), []byte("\x00\x00"), 2048, 1, 24)
    expected := []byte("\x00\xf7\x59\xff\x47\xd1\x4d\xd0\x36\x65\xd5\x94\x3c\xb3\xc4\xa3\x9a\x25\x55\xc0\x2a\xed\x66\xe1")
    if bytes.Compare(key, expected) != 0 {
        t.Fatalf("expected key '%x', but found '%x'", expected, key)
    }
}
