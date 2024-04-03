package threefish

import (
    "encoding/hex"
    "errors"
    "testing"
)

func TestThreefish512(t *testing.T) {
    t.Run("key too short", func(t *testing.T) {
            key := make([]byte, BlockSize512-1)
            tweak := make([]byte, tweakSize)

            block, err := NewCipher512(key, tweak)
            if block != nil {
                t.Fatal("expected cipher to be nil")
            }
            if err == nil {
                t.Fatal("expected error to be non-nil")
                if !errors.Is(err, KeySizeError(BlockSize512)) {
                    t.Fatalf("error should be %s", KeySizeError(BlockSize512))
                }
            }
        },
    )

    t.Run(
        "key too long",
        func(t *testing.T) {
            key := make([]byte, BlockSize512+1)
            tweak := make([]byte, tweakSize)

            block, err := NewCipher512(key, tweak)
            if block != nil {
                t.Fatal("expected cipher to be nil")
            }
            if err == nil {
                t.Fatal("expected error to be non-nil")
                if !errors.Is(err, KeySizeError(BlockSize512)) {
                    t.Fatalf("error should be %s", KeySizeError(BlockSize512))
                }
            }
        },
    )

    t.Run(
        "tweak too short",
        func(t *testing.T) {
            key := make([]byte, BlockSize512)
            tweak := make([]byte, tweakSize-1)

            block, err := NewCipher512(key, tweak)
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
            key := make([]byte, BlockSize512)
            tweak := make([]byte, tweakSize+1)

            block, err := NewCipher512(key, tweak)
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
            key := make([]byte, BlockSize512)
            tweak := make([]byte, tweakSize)

            block, err := NewCipher512(key, tweak)
            if block == nil {
                t.Fatal("expected cipher to be non-nil")
            }
            if err != nil {
                t.Fatal("expected error to be nil")
            }

            if block.BlockSize() != (512 / 8) {
                t.Fatal("block size getter returned incorrect block size")
            }

            message := make([]byte, BlockSize512)
            ciphertext := make([]byte, BlockSize512)

            block.Encrypt(ciphertext, message)
            if hex.EncodeToString(ciphertext) != "b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe" {
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
            key, err := hex.DecodeString("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
            if err != nil {
                t.Fatal("failed to decode key string")
            }
            tweak, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
            if err != nil {
                t.Fatal("failed to decode tweak string")
            }

            block, err := NewCipher512(key, tweak)
            if block == nil {
                t.Fatal("expected cipher to be non-nil")
            }
            if err != nil {
                t.Fatal("expected error to be nil")
            }

            message, err := hex.DecodeString("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0")
            if err != nil {
                t.Fatal("failed to decode message string")
            }
            ciphertext := make([]byte, BlockSize512)

            block.Encrypt(ciphertext, message)
            if hex.EncodeToString(ciphertext) != "e304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d" {
                t.Fatal("ciphertext does not match expected value")
            }

            block.Decrypt(ciphertext, ciphertext)
            if hex.EncodeToString(ciphertext) != hex.EncodeToString(message) {
                t.Fatal("decrypted message does not match original message")
            }
        },
    )
}

func BenchmarkThreefish512(b *testing.B) {
    key := make([]byte, BlockSize512)
    tweak := make([]byte, tweakSize)
    message := make([]byte, BlockSize512)

    block, err := NewCipher512(key, tweak)
    if err != nil {
        b.Fatalf("failed to create cipher with error: %s", err)
    }

    b.Run(
        "encrypt",
        func(b *testing.B) {
            ciphertext := make([]byte, BlockSize512)

            for n := 0; n < b.N; n++ {
                block.Encrypt(ciphertext, message)
                b.SetBytes(BlockSize512)
            }
        },
    )

    b.Run(
        "decrypt",
        func(b *testing.B) {
            ciphertext := make([]byte, BlockSize512)

            for n := 0; n < b.N; n++ {
                block.Decrypt(ciphertext, ciphertext)
                b.SetBytes(BlockSize512)
            }
        },
    )
}
