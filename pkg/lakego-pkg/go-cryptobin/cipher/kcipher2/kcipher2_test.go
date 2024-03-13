package kcipher2

import (
    "bytes"
    "testing"
    "encoding/hex"
)

var tests = []struct {
    key       string
    iv        string
    keystream string
}{
    // http://tools.ietf.org/html/rfc7008
    {
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "F871EBEF945B7272E40C04941DFF05370B981A59FBC8AC57566D3B02C179DBB43B46F1F033554C725DE68BCC9872858F575496024062F0E9F932C998226DB6BA",
    },
    {
        "A37B7D012F897076FE08C22D142BB2CF",
        "33A6EE60E57927E08B45CC4CA30EDE4A",
        "60E9A6B67B4C2524FE726D44AD5B402E31D0D1BA5CA233A4AFC74BE7D6069D364A75BB6CD8D5B7F038AAAA284AE4CD2FE2E5313DFC6CCD8F9D2484F20F86C50D",
    },

    {
        "3D62E9B18E5B042F42DF43CC7175C96E",
        "777CEFE4541300C8ADCACA8A0B48CD55",
        "690F108D84F44AC7BF257BD7E394F6C9AA1192C38E200C6E073C8078AC18AAD1D4B8DADE688023682FA4207683DEA5A44C1D95EAE959F5B42611F41EA40F0A58",
    },
}

func TestKCipher2(t *testing.T) {
    for _, tt := range tests {

        key, _ := hex.DecodeString(tt.key)
        iv, _ := hex.DecodeString(tt.iv)
        stream, _ := hex.DecodeString(tt.keystream)

        k2, _ := NewCipher(key[:], iv[:])

        var data [64]byte

        // xoring keystream with 0s (in data) gives us the keystream bytes in data
        k2.XORKeyStream(data[:], data[:])

        if !bytes.Equal(data[:], stream) {
            t.Errorf("known keystream failed:\ngot : % 02x\nwant: % 02x", data[:], stream)
        }
    }
}
