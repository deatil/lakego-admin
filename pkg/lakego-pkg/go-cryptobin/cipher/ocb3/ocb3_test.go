package ocb3

import (
    "time"
    "bytes"
    "testing"
    "crypto/aes"
    "crypto/rand"
    "encoding/binary"
    "encoding/hex"
    mrand "math/rand"
)

// Test vectors from RFC 7253.
var tests = []struct {
    nonceSize, tagSize int
    key                string
    nonce              string
    ad                 string
    plaintext          string
    ciphertext         string
}{
    0:  {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA99887766554433221100", "", "", "785407BFFFC8AD9EDCC5520AC9111EE6"},
    1:  {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA99887766554433221101", "0001020304050607", "0001020304050607", "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009"},
    2:  {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA99887766554433221102", "0001020304050607", "", "81017F8203F081277152FADE694A0A00"},
    3:  {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA99887766554433221103", "", "0001020304050607", "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9"},
    4:  {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA99887766554433221104", "000102030405060708090A0B0C0D0E0F", "000102030405060708090A0B0C0D0E0F", "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358"},
    5:  {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA99887766554433221105", "000102030405060708090A0B0C0D0E0F", "", "8CF761B6902EF764462AD86498CA6B97"},
    6:  {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA99887766554433221106", "", "000102030405060708090A0B0C0D0E0F", "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D"},
    7:  {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA99887766554433221107", "000102030405060708090A0B0C0D0E0F1011121314151617", "000102030405060708090A0B0C0D0E0F1011121314151617", "1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F"},
    8:  {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA99887766554433221108", "000102030405060708090A0B0C0D0E0F1011121314151617", "", "6DC225A071FC1B9F7C69F93B0F1E10DE"},
    9:  {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA99887766554433221109", "", "000102030405060708090A0B0C0D0E0F1011121314151617", "221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF"},
    10: {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA9988776655443322110A", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240"},
    11: {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA9988776655443322110B", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "", "FE80690BEE8A485D11F32965BC9D2A32"},
    12: {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA9988776655443322110C", "", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF"},
    13: {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA9988776655443322110D", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60"},
    14: {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA9988776655443322110E", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "", "C5CD9D1850C141E358649994EE701B68"},
    15: {12, 16, "000102030405060708090A0B0C0D0E0F", "BBAA9988776655443322110F", "", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479"},
    16: {12, 12, "0F0E0D0C0B0A09080706050403020100", "BBAA9988776655443322110D", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "1792A4E31E0755FB03E31B22116E6C2DDF9EFD6E33D536F1A0124B0A55BAE884ED93481529C76B6AD0C515F4D1CDD4FDAC4F02AA"},
}

func unhex(t *testing.T, s string) []byte {
    p, err := hex.DecodeString(s)
    if err != nil {
        t.Fatal(err)
    }
    return p
}

func TestSeal(t *testing.T) {
    for i, tc := range tests {
        c, err := aes.NewCipher(unhex(t, tc.key))
        if err != nil {
            t.Fatal(err)
        }
        aead, err := NewWithNonceAndTagSize(c, tc.nonceSize, tc.tagSize)
        if err != nil {
            t.Fatal(err)
        }
        nonce := unhex(t, tc.nonce)
        plaintext := unhex(t, tc.plaintext)
        ad := unhex(t, tc.ad)
        want := unhex(t, tc.ciphertext)
        got := aead.Seal(nil, nonce, plaintext, ad)
        if !bytes.Equal(want, got) {
            t.Fatalf("%d: expected %x, got %x", i, want, got)
        }
    }
}

func TestOpen(t *testing.T) {
    for i, tc := range tests {
        c, err := aes.NewCipher(unhex(t, tc.key))
        if err != nil {
            t.Fatal(err)
        }
        aead, err := NewWithNonceAndTagSize(c, tc.nonceSize, tc.tagSize)
        if err != nil {
            t.Fatal(err)
        }
        nonce := unhex(t, tc.nonce)
        ciphertext := unhex(t, tc.ciphertext)
        ad := unhex(t, tc.ad)
        got, err := aead.Open(nil, nonce, ciphertext, ad)
        if err != nil {
            t.Fatalf("%d: unexpected error: %v", i, err)
        }
        want := unhex(t, tc.plaintext)
        if !bytes.Equal(want, got) {
            t.Fatalf("%d: expected %x, got %x", i, want, got)
        }
    }
}

func TestOpenFailure(t *testing.T) {
    // In the following test cases, the key, nonce, ad, and
    // original plaintext are all
    //
    //    for i := range x {
    //        x[i] = byte(i)
    //    }
    //
    for _, tc := range []struct {
        name       string
        key        string
        nonce      string
        ciphertext string
        ad         string
    }{
        {"invalid key", "100102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000102030405060708090a0b", "b271bb69c3e1b79629cb362807319a03d4439c9923f10f8dbad35e2b3d8aa1ee898e14edc1043d15a958741a7cb46f165a16941dc195a75ad602cb10d2b5fc4aec775d50f32d6a60e0b7cecabe584189c69050d9e480f285d9962f35e20989d40b2da44b7df9b51f2e7fca62f72388abebc8af72", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"},
        {"invalid nonce", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "100102030405060708090a0b", "b271bb69c3e1b79629cb362807319a03d4439c9923f10f8dbad35e2b3d8aa1ee898e14edc1043d15a958741a7cb46f165a16941dc195a75ad602cb10d2b5fc4aec775d50f32d6a60e0b7cecabe584189c69050d9e480f285d9962f35e20989d40b2da44b7df9b51f2e7fca62f72388abebc8af72", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"},
        {"invalid ciphertext", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000102030405060708090a0b", "a271bb69c3e1b79629cb362807319a03d4439c9923f10f8dbad35e2b3d8aa1ee898e14edc1043d15a958741a7cb46f165a16941dc195a75ad602cb10d2b5fc4aec775d50f32d6a60e0b7cecabe584189c69050d9e480f285d9962f35e20989d40b2da44b7df9b51f2e7fca62f72388abebc8af72", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"},
        {"invalid ad", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000102030405060708090a0b", "b271bb69c3e1b79629cb362807319a03d4439c9923f10f8dbad35e2b3d8aa1ee898e14edc1043d15a958741a7cb46f165a16941dc195a75ad602cb10d2b5fc4aec775d50f32d6a60e0b7cecabe584189c69050d9e480f285d9962f35e20989d40b2da44b7df9b51f2e7fca62f72388abebc8af72", "100102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"},
        {"invalid tag", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000102030405060708090a0b", "b271bb69c3e1b79629cb362807319a03d4439c9923f10f8dbad35e2b3d8aa1ee898e14edc1043d15a958741a7cb46f165a16941dc195a75ad602cb10d2b5fc4aec775d50f32d6a60e0b7cecabe584189c69050d9e480f285d9962f35e20989d40b2da44b7df9b51f2e7fca62f72388abebc8af73", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"},
        {"short tag", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000102030405060708090a0b", "b271bb69c3e1b79629cb362807319a03d4439c9923f10f8dbad35e2b3d8aa1ee898e14edc1043d15a958741a7cb46f165a16941dc195a75ad602cb10d2b5fc4aec775d50f32d6a60e0b7cecabe584189c69050d9e480f285d9962f35e20989d40b2da44b7df9b51f2e7fca62f72388abebc8af", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"},
        {"tiny tag", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000102030405060708090a0b", "b271bb69c3e1b79629cb362807319a", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"},
    } {
        t.Run(tc.name, func(t *testing.T) {
            c, err := aes.NewCipher(unhex(t, tc.key))
            if err != nil {
                t.Fatal(err)
            }
            aead, err := New(c)
            if err != nil {
                t.Fatal(err)
            }
            nonce := unhex(t, tc.nonce)
            ciphertext := unhex(t, tc.ciphertext)
            ad := unhex(t, tc.ad)
            _, err = aead.Open(nil, nonce, ciphertext, ad)
            if err != errOpen {
                t.Fatalf("unexpected error: %v", err)
            }
        })
    }
}

func TestFuzz(t *testing.T) {
    key := make([]byte, 32)
    if _, err := rand.Read(key); err != nil {
        panic(err)
    }
    c, err := aes.NewCipher(key)
    if err != nil {
        t.Fatal(err)
    }
    alice, err := New(c)
    if err != nil {
        t.Fatal(err)
    }
    bob, err := New(c)
    if err != nil {
        t.Fatal(err)
    }

    buf := make([]byte, 4096)
    if _, err := rand.Read(buf); err != nil {
        panic(err)
    }

    var timer *time.Timer
    if testing.Short() {
        timer = time.NewTimer(10 * time.Millisecond)
    } else {
        timer = time.NewTimer(2 * time.Second)
    }

    nonce := make([]byte, alice.NonceSize())
    var plaintext []byte
    var ciphertext []byte
    for i := 0; ; i++ {
        select {
        case <-timer.C:
            return
        default:
        }

        ad := sliceOf(buf)
        input := sliceOf(buf)

        binary.BigEndian.PutUint64(nonce, uint64(i))

        ciphertext = alice.Seal(ciphertext[:0], nonce, input, ad)
        plaintext, err = bob.Open(plaintext[:0], nonce, ciphertext, ad)
        if err != nil {
            t.Fatal(err)
        }
        if !bytes.Equal(plaintext, input) {
            t.Fatal("mismatch")
        }
    }
}

func sliceOf(p []byte) []byte {
    i := mrand.Intn(len(p)-1) + 1
    j := mrand.Intn(i)
    return p[j:i]
}

func BenchmarkSeal1K(b *testing.B) {
    benchmarkSeal(b, make([]byte, 1*1024))
}

func BenchmarkSeal8K(b *testing.B) {
    benchmarkSeal(b, make([]byte, 8*1024))
}

func benchmarkSeal(b *testing.B, buf []byte) {
    b.SetBytes(int64(len(buf)))

    var key [16]byte
    var nonce [12]byte
    var ad [13]byte
    c, err := aes.NewCipher(key[:])
    if err != nil {
        b.Fatal(err)
    }
    aead, err := New(c)
    if err != nil {
        b.Fatal(err)
    }
    var out []byte

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        out = aead.Seal(out[:0], nonce[:], buf, ad[:])
    }
}

func BenchmarkOpen1K(b *testing.B) {
    benchmarkOpen(b, make([]byte, 1*1024))
}

func BenchmarkOpen8K(b *testing.B) {
    benchmarkOpen(b, make([]byte, 8*1024))
}

func benchmarkOpen(b *testing.B, buf []byte) {
    b.SetBytes(int64(len(buf)))

    var key [16]byte
    var nonce [12]byte
    var ad [13]byte
    c, err := aes.NewCipher(key[:])
    if err != nil {
        b.Fatal(err)
    }
    aead, err := New(c)
    if err != nil {
        b.Fatal(err)
    }
    var out []byte
    out = aead.Seal(out[:0], nonce[:], buf, ad[:])

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := aead.Open(buf[:0], nonce[:], out, ad[:])
        if err != nil {
            b.Errorf("Open: %v", err)
        }
    }
}
