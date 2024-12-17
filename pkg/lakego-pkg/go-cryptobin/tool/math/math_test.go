package math

import (
    "math"
    "math/big"
    "math/rand"
    "testing"
    "encoding/binary"
)

func Test_Min(t * testing.T) {
    a := 123
    b := 125
    res := Min(a, b)
    if res != a {
        t.Errorf("got %d, want %d", res, a)
    }
}

func Test_Max(t * testing.T) {
    a := 123
    b := 125
    res := Max(a, b)
    if res != b {
        t.Errorf("got %d, want %d", res, b)
    }
}

func Test_Contains(t * testing.T) {
    a := []int{123, 133, 125}
    b := 125
    if res := Contains(a, b); !res {
        t.Errorf("got %v, want %v", res, true)
    }
}

func Test_Sum(t * testing.T) {
    a := []int{123, 133, 125}
    check := 381

    res := Sum(a...)

    if res != check {
        t.Errorf("got %d, want %d", res, check)
    }
}

func Test_E(t * testing.T) {
    e_string := "2.7182818284590452353602874713526624977572470936999595749669676277240766303535475945713821785251664274"
    e := E(200)
    e_str := e.FloatString(100)
    if e_string != e_str {
        t.Errorf("e = %s\ne_string = %s", e_str, e_string)
    }
}

func Test_Phi(t * testing.T) {
    phi_string := "1.61803398874989484820458683436563811772030917980576286213544862270526046281890244970720720418939113748475"
    phi := Phi(2000)
    phi_str := phi.FloatString(104)
    if phi_string != phi_str {
        t.Errorf("phi = %s\nphi_string = %s", phi, phi_str)
    }
}

func Test_Ceil(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    for j := 0; j < max; j++ {
        f := random.NormFloat64()
        r := new(big.Rat).SetFloat64(f)
        b := new(big.Float).SetFloat64(math.Ceil(f))
        i, _ := b.Int(nil)
        if i.Cmp(Ceil(r)) != 0 {
            t.Errorf("Ceil(%v) = %v != %v", r, Ceil(r), i)
        }
        // Ensure operation does not modify argument
        s := new(big.Rat).SetFloat64(f)
        if r.Cmp(s) != 0 {
            t.Errorf("%v != %v", r, s)
        }
    }
    for j := 0; j < max; j++ {
        f := random.Int63()
        r := new(big.Rat).SetInt64(f)
        i := new(big.Int).SetUint64(uint64(f))
        if i.Cmp(Ceil(r)) != 0 {
            t.Errorf("Ceil(%v) = %v != %v", r, Ceil(r), i)
        }
    }
}

func Test_Floor(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    for j := 0; j < max; j++ {
        f := random.NormFloat64()
        r := new(big.Rat).SetFloat64(f)
        b := new(big.Float).SetFloat64(math.Floor(f))
        i, _ := b.Int(nil)
        if i.Cmp(Floor(r)) != 0 {
            t.Errorf("Floor(%v) = %v != %v", r, Floor(r), i)
        }

        // Ensure operation does not modify argument
        s := new(big.Rat).SetFloat64(f)
        if r.Cmp(s) != 0 {
            t.Errorf("%v != %v", r, s)
        }
    }
    for j := 0; j < max; j++ {
        f := random.Int63()
        r := new(big.Rat).SetInt64(f)
        i := new(big.Int).SetUint64(uint64(f))
        if i.Cmp(Floor(r)) != 0 {
            t.Errorf("Floor(%v) = %v != %v", r, Floor(r), i)
        }
    }
}

func Test_Odd(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    for j := 0; j < max; j++ {
        i := uint64(random.Int63())
        x := new(big.Int).SetUint64(i)
        y := Odd(x)

        if i % 2 == 0 {
            if y.Sub(y, one).Cmp(x) != 0 {
                t.Errorf("Odd(%v) != %v", x, y)
            }
        } else {
            if x.Cmp(y) != 0 {
                t.Errorf("Odd(%v) != %v", x, y)
            }
        }

        // Ensure operation does not modify argument
        z := new(big.Int).SetUint64(i)
        if x.Cmp(z) != 0 {
            t.Errorf("%v != %v", x, z)
        }
    }
}

var random = rand.New(rand.NewSource(99))

func Uint64() uint64 {
    buf := make([]byte, 8)
    random.Read(buf) // Always succeeds, no need to check error
    return binary.LittleEndian.Uint64(buf)
}

func rotateLeft32(x uint32, r uint) uint32 {
    return (x << r) | (x >> (32 - r))
}

func rotateRight32(x uint32, r uint) uint32 {
    return (x >> r) | (x << (32 - r))
}

func rotateLeft64(x uint64, r uint) uint64 {
    return (x << r) | (x >> (64 - r))
}

func rotateRight64(x uint64, r uint) uint64 {
    return (x >> r) | (x << (64 - r))
}

func Test_Mask(t *testing.T) {
    if Mask(8).Uint64() != uint64(math.MaxUint8) {
        t.Errorf("mask(8) != MaxUint8: %v != %v", Mask(8), math.MaxUint8)
    }
    if Mask(16).Uint64() != uint64(math.MaxUint16) {
        t.Errorf("mask(16) != MaxUint15: %v != %v", Mask(16), math.MaxUint16)
    }
    if Mask(32).Uint64() != uint64(math.MaxUint32) {
        t.Errorf("mask(32) != MaxUint32: %v != %v", Mask(32), uint64(math.MaxUint32))
    }
    var maxUint64 uint64 = math.MaxUint64 // overflows assigned variable unless type is explicit!
    if Mask(64).Uint64() != maxUint64 {
        t.Errorf("mask(64) != MaxUint64: %v != %v", Mask(64), maxUint64)
    }
}

var max = 5000

func Test_RotateLeft32(t *testing.T) {
    mask := Mask(32)
    x := new(big.Int)
    for i := 1; i < max; i++ {
        for r := uint(0); r < uint(33); r++ {
            z := random.Uint32()
            x := RotateLeft(x.SetUint64(uint64(z)), r, 32, mask)
            y := uint64(rotateLeft32(z, r))
            if x.Uint64() != y {
                t.Errorf("(z, r) = (%v, %v): %v != %v", z, r, x, y)
            }
        }
    }
}

// TODO: change tests to convert y to a big.Int and do comparison
// that way to ensure that there isn't extra precision in x that
// is disappearing due to conversion to smaller data type like
// uint64 or uint32.
func Test_RotateRight32(t * testing.T) {
    mask := Mask(32)
    x := new(big.Int)
    for i := 1; i < max; i++ {
        for r := uint(0); r < uint(33); r++ {
            z := random.Uint32()
            x := RotateRight(x.SetUint64(uint64(z)), r, 32, mask)
            y := uint64(rotateRight32(z, r))
            if x.Uint64() != y {
                t.Errorf("(z, r) = (%v, %v): %v != %v", z, r, x, y)
            }
        }
    }
}

func Test_RotateLeft64(t * testing.T) {
    mask := Mask(64)
    x := new(big.Int)
    for i := 1; i < max; i++ {
        for r := uint(0); r < uint(65); r++ {
            z := Uint64()
            x := RotateLeft(x.SetUint64(z), r, 64, mask)
            y := rotateLeft64(z, r)
            if x.Uint64() != y {
                t.Errorf("(z, r) = (%v, %v): %v != %v", z, r, x, y)
            }
        }
    }
}

func Test_RotateRight64(t * testing.T) {
    mask := Mask(64)
    x := new(big.Int)
    for i := 1; i < max; i++ {
        for r := uint(0); r < uint(65); r++ {
            z := Uint64()
            x := RotateRight(x.SetUint64(z), r, 64, mask)
            y := rotateRight64(z, r)
            if x.Uint64() != y {
                t.Errorf("(z, r) = (%v, %v): %v != %v", z, r, x, y)
            }
        }
    }
}

func Test_Round(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    for j := 0; j < max; j++ {
        f := random.NormFloat64()
        int_, frac := math.Modf(f)

        r := new(big.Rat).SetFloat64(f)
        i := new(big.Int)
        if frac >= 0.5 {
            i.SetInt64(int64(int_) + 1)
        } else {
            i.SetInt64(int64(int_))
        }

        if i.Cmp(Round(r)) != 0 {
            // t.Errorf("Round(%v) = %v != %v", r, Round(r), i)
        }

        // Ensure operation does not modify argument
        s := new(big.Rat).SetFloat64(f)
        if r.Cmp(s) != 0 {
            t.Errorf("%v != %v", r, s)
        }
    }

    for j := 0; j < max; j++ {
        f := random.Int63()
        r := new(big.Rat).SetInt64(f)
        i := new(big.Int).SetInt64(int64(f))

        ii := new(big.Int).Add(i, one)

        if ii.Cmp(Round(r)) != 0 {
            t.Errorf("Round(%v) = %v != %v", r, Round(r), ii)
        }
    }
}

func Test_Sqrt(t *testing.T) {
    percent_error := new(big.Rat)
    max := new(big.Rat).SetFloat64(0.00005)
    r := new(big.Rat)
    i := new(big.Int)
    for j, rounds := uint64(0), uint64(2000); j < rounds; j++ {
        sqrt := Sqrt(j, 200)
        r.SetInt(i.SetUint64(j))
        percent_error.Mul(sqrt, sqrt)
        if j != 0 {
            percent_error.Sub(percent_error, r)
            percent_error.Quo(percent_error, r)
        }

        if percent_error.Cmp(max) == 1 {
            // We can use the usual fmt.Printf verbs since big.Float implements fmt.Formatter
            rf, _ := r.Float64()
            percent_error_f, _ := percent_error.Float64()

            t.Errorf("sqrt(%d) = %.5f, %% error = %.25f\n", j, rf, percent_error_f)
        }
    }
}
