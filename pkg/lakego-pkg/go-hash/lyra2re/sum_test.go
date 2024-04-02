package lyra2re

import (
    "fmt"
    "testing"
)

func Test_SumV1(t *testing.T) {
    tests := []struct {
        name string
        in   []byte
        out  string
    }{
        {
            name: "Basic",
            in:   []byte{0x34, 0x6e, 0x80, 0x88, 0x0e, 0xcc, 0x9e, 0x84, 0xce, 0x60, 0x22, 0xcf, 0x37, 0x56, 0xa1, 0xdf, 0x17, 0x56, 0x84, 0x0e, 0xf7, 0xea, 0x65, 0xc6, 0x44, 0xc9, 0x9f, 0x6d, 0x3d, 0xa3, 0x1f, 0x2b},
            out:  "52e973e71f42c73a1adea7f149ef8c070b24f48c6a03b7877babd1fa761ba3ee",
        },
    }

    for _, test := range tests {
        test := test
        t.Run(test.name, func(t *testing.T) {
            sum, err := Sum(test.in)
            if err != nil {
                t.Errorf("Error while summing: %v", err)
            }

            got := fmt.Sprintf("%x", sum)
            if got != test.out {
                t.Errorf("not match, got %x, want %s", sum, test.out)
            }
        })
    }
}
