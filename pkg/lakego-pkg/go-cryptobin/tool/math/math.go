package math

import (
    "math"
    "math/big"
)

var (
    zero = big.NewInt(0)
    half = big.NewRat(1, 2)
    one  = big.NewInt(1)
    two  = big.NewInt(2)
)

type Signed interface {
    ~int | ~int8 | ~int16 | ~int32 | ~int64
}

type Unsigned interface {
    ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

type Float interface {
    ~float32 | ~float64
}

type Complex interface {
    ~complex64 | ~complex128
}

type Integer interface {
    Signed | Unsigned
}

type IntegerFloat interface {
    Integer | Float
}

type Ordered interface {
    Integer | Float | ~string
}

type MathInteger interface {
    Integer | Float | Complex
}

func Min[T IntegerFloat](a, b T) T {
    if a < b {
        return a
    }

    return b
}

func Max[T IntegerFloat](a, b T) T {
    if a > b {
        return a
    }

    return b
}

// Contains
func Contains[T Ordered](items []T, item T) bool {
    for _, v := range items {
        if v == item {
            return true
        }
    }

    return false
}

// Sum
func Sum[T MathInteger](s ...T) (sum T) {
    for _, v := range s {
        sum += v
    }

    return
}

func E(rounds uint) *big.Rat {
    acc := big.NewRat(2, 1)
    f := big.NewRat(1, 1)

    for i := int64(2); i < int64(rounds); i++ {
        f.Mul(f, big.NewRat(1, i))
        acc.Add(acc, f)
    }

    return acc
}

func Phi(precision uint) *big.Rat {
    e := Sqrt(5, precision)

    e.Add(e, big.NewRat(1, 1))
    e.Quo(e, big.NewRat(2, 1))

    return e
}

func Ceil(n *big.Rat) *big.Int {
    if n.IsInt() {
        return new(big.Int).Set(n.Num())
    } else {
        r := new(big.Int)
        return r.Div(n.Num(), n.Denom()).Add(r, one)
    }
}

func Floor(n *big.Rat) *big.Int {
    r := new(big.Int)
    return r.Div(n.Num(), n.Denom())
}

func Odd(n *big.Int) *big.Int {
    buffer := big.NewInt(1)

    if buffer.Mod(n, two).Cmp(zero) == 0 {
        return n.Add(n, one)
    }

    return n
}

func Mask(s uint) *big.Int {
    mask := new(big.Int).Lsh(one, s)
    mask.Sub(mask, one)

    return mask
}

func RotateLeft(x *big.Int, r uint, s uint, mask *big.Int) *big.Int {
    masked := new(big.Int).And(x, mask)

    left := new(big.Int).Lsh(masked, r)
    left.And(left, mask)

    right := new(big.Int).Rsh(masked, s - r)

    return left.Or(left, right)
}

func RotateRight(i *big.Int, r uint, s uint, mask *big.Int) *big.Int {
    return RotateLeft(i, s - r, s, mask)
}

func Round(n *big.Rat) *big.Int {
    r := new(big.Rat).Set(n)

    if r.Sign() < 0 {
        r.Sub(n, half)
    } else {
        r.Add(n, half)
    }

    return Ceil(r)
}

func Sqrt(n uint64, p uint) *big.Rat {
    if n == 0 {
        return big.NewRat(0, 1)
    }

    steps := int(math.Log2(float64(p)))

    // Initialize values we need for the computation.
    n_big := new(big.Rat).SetInt(new(big.Int).SetUint64(n))
    half := big.NewRat(1, 2)

    // Use 1 as the initial estimate.
    x := big.NewRat(1, 1)

    t := new(big.Rat)

    for i := 0; i <= steps; i++ {
        t.Quo(n_big, x)
        t.Add(x, t)
        x.Mul(half, t)
    }

    return x
}

