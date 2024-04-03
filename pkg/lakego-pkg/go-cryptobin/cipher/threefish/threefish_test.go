package threefish

import (
    "fmt"
    "bytes"
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

type testData struct {
    key []byte
    tweak []byte
    pt []byte
    ct []byte
}

func Test_Check(t *testing.T) {
   tests := []testData{
        // 256
        {
           make([]byte, BlockSize256),
           make([]byte, tweakSize),
           make([]byte, BlockSize256),
           fromHex("84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8"),
        },
        {
           fromHex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
           fromHex("000102030405060708090a0b0c0d0e0f"),
           fromHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"),
           fromHex("e0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df"),
        },

        // 512
        {
           make([]byte, BlockSize512),
           make([]byte, tweakSize),
           make([]byte, BlockSize512),
           fromHex("b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"),
        },
        {
           fromHex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
           fromHex("000102030405060708090a0b0c0d0e0f"),
           fromHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0"),
           fromHex("e304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d"),
        },

        // 1024
        {
           make([]byte, BlockSize1024),
           make([]byte, tweakSize),
           make([]byte, BlockSize1024),
           fromHex("f05c3d0a3d05b304f785ddc7d1e036015c8aa76e2f217b06c6e1544c0bc1a90df0accb9473c24e0fd54fea68057f43329cb454761d6df5cf7b2e9b3614fbd5a20b2e4760b40603540d82eabc5482c171c832afbe68406bc39500367a592943fa9a5b4a43286ca3c4cf46104b443143d560a4b230488311df4feef7e1dfe8391e"),
        },
        {
           fromHex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
           fromHex("000102030405060708090a0b0c0d0e0f"),
           fromHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180"),
           fromHex("a6654ddbd73cc3b05dd777105aa849bce49372eaaffc5568d254771bab85531c94f780e7ffaae430d5d8af8c70eebbe1760f3b42b737a89cb363490d670314bd8aa41ee63c2e1f45fbd477922f8360b388d6125ea6c7af0ad7056d01796e90c83313f4150a5716b30ed5f569288ae974ce2b4347926fce57de44512177dd7cde"),
        },
    }

    for i, test := range tests {
        block, err := NewCipher(test.key, test.tweak)
        if block == nil {
            t.Fatal(fmt.Sprintf("[%d] expected cipher to be non-nil", i))
        }
        if err != nil {
            t.Fatal(fmt.Sprintf("[%d] expected error to be nil", i))
        }

        ciphertext := make([]byte, len(test.pt))

        block.Encrypt(ciphertext, test.pt)
        if !bytes.Equal(ciphertext, test.ct) {
            t.Errorf("[%d] Encrypt fail, got %x, want %x", i, ciphertext, test.ct)
        }

        block.Decrypt(ciphertext, ciphertext)
        if !bytes.Equal(ciphertext, test.pt) {
            t.Errorf("[%d] Decrypt fail, got %x, want %x", i, ciphertext, test.pt)
        }
    }

}
