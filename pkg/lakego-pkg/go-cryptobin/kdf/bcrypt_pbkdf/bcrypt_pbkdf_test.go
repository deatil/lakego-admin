package bcrypt_pbkdf

import (
    "fmt"
    "testing"
)

func Test_Pbkdf(t *testing.T) {
    type args struct {
        password []byte
        salt     []byte
        rounds   int
        keyLen   int
    }

    tests := []struct {
        name string
        args args
        want string
    }{
        {"bcrypt_pbkdf case 1", args{[]byte("test password"), []byte("test salt"), 2, 12}, "5b670a9e4b77db7d5337b0e1"},
        {"bcrypt_pbkdf case 2", args{[]byte("test password"), []byte("test salt"), 4, 16}, "986f10498e60390aedcd2bffb9a3edc0"},
        {"bcrypt_pbkdf case 3", args{[]byte("test password"), []byte("test salt"), 12, 24}, "2804548a13f0b6b8c72704f761f48e3af19d3fccbc87b91e"},
        {"bcrypt_pbkdf case 4", args{[]byte("test password"), []byte("test salt"), 24, 32}, "6ce30248bcce32d3f1239126607c49c1af6473c5b01ea7285af55a53b36a6523"},
        {"bcrypt_pbkdf case 5", args{[]byte("test password"), []byte("test salt"), 56, 120}, "b221505b7759a4ab8661b076c2f2260efb53e807ee4a41a8fc2e0c73c8299de8c49d414c4e5e7e57b459f63f5b10822d0a128f87086867d3937462e8c114aa37fa50009cc790c0abc7493e2401102abc2837adce1f7aa6d1d9d4a715716887eb23c68ca9c7dcccb9a8083ec3a76a2d176a809001788591b7"},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := Key(tt.args.password, tt.args.salt, tt.args.rounds, tt.args.keyLen)
            if err != nil {
                t.Fatal(err)
            }

            if fmt.Sprintf("%x", got) != tt.want {
                t.Errorf("Key(%v) = %x, want %s", tt.name, got, tt.want)
            }
        })
    }
}
