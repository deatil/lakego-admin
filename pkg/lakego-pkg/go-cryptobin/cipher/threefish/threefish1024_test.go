package threefish

import (
    "encoding/hex"
    "errors"
    "testing"
)

func TestThreefish1024(t *testing.T) {
    t.Run("key too short", func(t *testing.T) {
            key := make([]byte, BlockSize1024-1)
            tweak := make([]byte, tweakSize)

            block, err := NewCipher1024(key, tweak)
            if block != nil {
                t.Fatal("expected cipher to be nil")
            }
            if err == nil {
                t.Fatal("expected error to be non-nil")
                if !errors.Is(err, KeySizeError(BlockSize1024)) {
                    t.Fatalf("error should be %s", KeySizeError(BlockSize1024))
                }
            }
        },
    )

    t.Run(
        "key too long",
        func(t *testing.T) {
            key := make([]byte, BlockSize1024+1)
            tweak := make([]byte, tweakSize)

            block, err := NewCipher1024(key, tweak)
            if block != nil {
                t.Fatal("expected cipher to be nil")
            }
            if err == nil {
                t.Fatal("expected error to be non-nil")
                if !errors.Is(err, KeySizeError(BlockSize1024)) {
                    t.Fatalf("error should be %s", KeySizeError(BlockSize1024))
                }
            }
        },
    )

    t.Run(
        "tweak too short",
        func(t *testing.T) {
            key := make([]byte, BlockSize1024)
            tweak := make([]byte, tweakSize-1)

            block, err := NewCipher1024(key, tweak)
            if block != nil {
                t.Fatal("expected cipher to be nil")
            }
            if err == nil {
                t.Fatal("expected error to be non-nil")
                if !errors.Is(err, new(TweakSizeError)) {
                    t.Fatalf("error should be %s", new(TweakSizeError))
                }
            }
        },
    )

    t.Run(
        "tweak too long",
        func(t *testing.T) {
            key := make([]byte, BlockSize1024)
            tweak := make([]byte, tweakSize+1)

            block, err := NewCipher1024(key, tweak)
            if block != nil {
                t.Fatal("expected cipher to be nil")
            }
            if err == nil {
                t.Fatal("expected error to be non-nil")
                if !errors.Is(err, new(TweakSizeError)) {
                    t.Fatalf("error should be %s", new(TweakSizeError))
                }
            }
        },
    )

    t.Run(
        "empty key, tweak, and message",
        func(t *testing.T) {
            key := make([]byte, BlockSize1024)
            tweak := make([]byte, tweakSize)

            block, err := NewCipher1024(key, tweak)
            if block == nil {
                t.Fatal("expected cipher to be non-nil")
            }
            if err != nil {
                t.Fatal("expected error to be nil")
            }

            if block.BlockSize() != (1024 / 8) {
                t.Fatal("block size getter returned incorrect block size")
            }

            message := make([]byte, BlockSize1024)
            ciphertext := make([]byte, BlockSize1024)

            block.Encrypt(ciphertext, message)
            if hex.EncodeToString(ciphertext) != "f05c3d0a3d05b304f785ddc7d1e036015c8aa76e2f217b06c6e1544c0bc1a90df0accb9473c24e0fd54fea68057f43329cb454761d6df5cf7b2e9b3614fbd5a20b2e4760b40603540d82eabc5482c171c832afbe68406bc39500367a592943fa9a5b4a43286ca3c4cf46104b443143d560a4b230488311df4feef7e1dfe8391e" {
                t.Log(hex.EncodeToString(ciphertext))
                t.Fatal("ciphertext does not match expected value")
            }

            block.Decrypt(ciphertext, ciphertext)
            if hex.EncodeToString(ciphertext) != hex.EncodeToString(message) {
                t.Fatal("decrypted message does not match original message")
            }
        },
    )

    t.Run(
        "non-empty key, tweak, and message",
        func(t *testing.T) {
            key, err := hex.DecodeString("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
            if err != nil {
                t.Fatal("failed to decode key string")
            }
            tweak, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
            if err != nil {
                t.Fatal("failed to decode tweak string")
            }

            block, err := NewCipher1024(key, tweak)
            if block == nil {
                t.Fatal("expected cipher to be non-nil")
            }
            if err != nil {
                t.Fatal("expected error to be nil")
            }

            message, err := hex.DecodeString("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180")
            if err != nil {
                t.Fatal("failed to decode message string")
            }
            ciphertext := make([]byte, BlockSize1024)

            block.Encrypt(ciphertext, message)
            if hex.EncodeToString(ciphertext) != "a6654ddbd73cc3b05dd777105aa849bce49372eaaffc5568d254771bab85531c94f780e7ffaae430d5d8af8c70eebbe1760f3b42b737a89cb363490d670314bd8aa41ee63c2e1f45fbd477922f8360b388d6125ea6c7af0ad7056d01796e90c83313f4150a5716b30ed5f569288ae974ce2b4347926fce57de44512177dd7cde" {
                t.Fatal("ciphertext does not match expected value")
            }

            block.Decrypt(ciphertext, ciphertext)
            if hex.EncodeToString(ciphertext) != hex.EncodeToString(message) {
                t.Fatal("decrypted message does not match original message")
            }
        },
    )
}

func BenchmarkThreefish1024(b *testing.B) {
    key := make([]byte, BlockSize1024)
    tweak := make([]byte, tweakSize)
    message := make([]byte, BlockSize1024)

    block, err := NewCipher1024(key, tweak)
    if err != nil {
        b.Fatalf("failed to create cipher with error: %s", err)
    }

    b.Run(
        "encrypt",
        func(b *testing.B) {
            ciphertext := make([]byte, BlockSize1024)

            for n := 0; n < b.N; n++ {
                block.Encrypt(ciphertext, message)
                b.SetBytes(BlockSize1024)
            }
        },
    )

    b.Run(
        "decrypt",
        func(b *testing.B) {
            ciphertext := make([]byte, BlockSize1024)

            for n := 0; n < b.N; n++ {
                block.Decrypt(ciphertext, ciphertext)
                b.SetBytes(BlockSize1024)
            }
        },
    )
}
