package threefish

import (
    "encoding/hex"
    "errors"
    "testing"
)

func TestThreefish256(t *testing.T) {
    t.Run("key too short", func(t *testing.T) {
            key := make([]byte, BlockSize256-1)
            tweak := make([]byte, tweakSize)

            block, err := New256(key, tweak)
            if block != nil {
                t.Fatal("expected cipher to be nil")
            }
            if err == nil {
                t.Fatal("expected error to be non-nil")
                if !errors.Is(err, KeySizeError(BlockSize256)) {
                    t.Fatalf("error should be %s", KeySizeError(BlockSize256))
                }
            }
        },
    )

    t.Run(
        "key too long",
        func(t *testing.T) {
            key := make([]byte, BlockSize256+1)
            tweak := make([]byte, tweakSize)

            block, err := New256(key, tweak)
            if block != nil {
                t.Fatal("expected cipher to be nil")
            }
            if err == nil {
                t.Fatal("expected error to be non-nil")
                if !errors.Is(err, KeySizeError(BlockSize256)) {
                    t.Fatalf("error should be %s", KeySizeError(BlockSize256))
                }
            }
        },
    )

    t.Run(
        "tweak too short",
        func(t *testing.T) {
            key := make([]byte, BlockSize256)
            tweak := make([]byte, tweakSize-1)

            block, err := New256(key, tweak)
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
            key := make([]byte, BlockSize256)
            tweak := make([]byte, tweakSize+1)

            block, err := New256(key, tweak)
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
            key := make([]byte, BlockSize256)
            tweak := make([]byte, tweakSize)

            block, err := New256(key, tweak)
            if block == nil {
                t.Fatal("expected cipher to be non-nil")
            }
            if err != nil {
                t.Fatal("expected error to be nil")
            }

            if block.BlockSize() != (256 / 8) {
                t.Fatal("block size getter returned incorrect block size")
            }

            message := make([]byte, BlockSize256)
            ciphertext := make([]byte, BlockSize256)

            block.Encrypt(ciphertext, message)
            if hex.EncodeToString(ciphertext) != "84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8" {
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
            key, err := hex.DecodeString("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
            if err != nil {
                t.Fatal("failed to decode key string")
            }
            tweak, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
            if err != nil {
                t.Fatal("failed to decode tweak string")
            }

            block, err := New256(key, tweak)
            if block == nil {
                t.Fatal("expected cipher to be non-nil")
            }
            if err != nil {
                t.Fatal("expected error to be nil")
            }

            message, err := hex.DecodeString("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
            if err != nil {
                t.Fatal("failed to decode message string")
            }
            ciphertext := make([]byte, BlockSize256)

            block.Encrypt(ciphertext, message)
            if hex.EncodeToString(ciphertext) != "e0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df" {
                t.Fatal("ciphertext does not match expected value")
            }

            block.Decrypt(ciphertext, ciphertext)
            if hex.EncodeToString(ciphertext) != hex.EncodeToString(message) {
                t.Fatal("decrypted message does not match original message")
            }
        },
    )
}

func BenchmarkThreefish256(b *testing.B) {
    key := make([]byte, BlockSize256)
    tweak := make([]byte, tweakSize)
    message := make([]byte, BlockSize256)

    block, err := New256(key, tweak)
    if err != nil {
        b.Fatalf("failed to create cipher with error: %s", err)
    }

    b.Run(
        "encrypt",
        func(b *testing.B) {
            ciphertext := make([]byte, BlockSize256)

            for n := 0; n < b.N; n++ {
                block.Encrypt(ciphertext, message)
                b.SetBytes(BlockSize256)
            }
        },
    )

    b.Run(
        "decrypt",
        func(b *testing.B) {
            ciphertext := make([]byte, BlockSize256)

            for n := 0; n < b.N; n++ {
                block.Decrypt(ciphertext, ciphertext)
                b.SetBytes(BlockSize256)
            }
        },
    )
}
