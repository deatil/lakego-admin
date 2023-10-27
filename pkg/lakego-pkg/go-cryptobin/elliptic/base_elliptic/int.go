package base_elliptic

import (
    "math/big"
)

var (
    one = big.NewInt(1)
)

type bfi struct {
    v *big.Int
}

func newBFI() *bfi {
    return &bfi{new(big.Int)}
}
func newBFI64(x int64) *bfi {
    return &bfi{big.NewInt(x)}
}
func copyBFI(v *big.Int) *bfi {
    return &bfi{new(big.Int).Set(v)}
}
func wrapBFI(v *big.Int) *bfi {
    return &bfi{v}
}

func (z *bfi) BitLen() int {
    return z.v.BitLen()
}

func (z *bfi) Set(o *bfi) *bfi {
    z.v.Set(o.v)
    return z
}

func (z *bfi) SetBigInt(o *big.Int) *bfi {
    z.v.Set(o)
    return z
}

func (z *bfi) SetInt(x int64) *bfi {
    z.v.SetInt64(x)
    return z
}

func (z *bfi) Clone() *bfi {
    return copyBFI(z.v)
}
func (z *bfi) CloneBigInt() *big.Int {
    return new(big.Int).Set(z.v)
}

// Cmp compares x and y and returns:
//
//  -1 if x <  y
//   0 if x == y
//  +1 if x >  y
func (x *bfi) Cmp(y *bfi) int {
    return x.v.Cmp(y.v)
}

func (z *bfi) DivMod(num, den, p *bfi) *bfi {
    inv, _ := _extended_gcd(den, p)
    z.Mul(inv, num)
    return z
}

func (z *bfi) Add(x, y *bfi) *bfi {
    z.v.Xor(x.v, y.v)
    return z
}

func (z *bfi) Mul(self, y *bfi) *bfi {
    acc := new(big.Int)
    shift := uint(0)

    o := big.NewInt(0).Set(y.v)
    tmp := big.NewInt(0)

    for o.Sign() > 0 {
        if o.Bit(0) != 0 {
            acc.Xor(acc, tmp.Lsh(self.v, shift))
        }
        shift++
        o.Rsh(o, 1)
    }

    z.SetBigInt(acc)
    return z
}

func (z *bfi) Mod(self, base *bfi) *bfi {
    _, r := _bf_div(self, base)
    z.SetBigInt(r.v)
    return z
}

func (z *bfi) Div(self, o *bfi) *bfi {
    q, _ := _bf_div(self, o)
    z.Set(q)
    return z
}

func _extended_gcd(a_, b_ *bfi) (*bfi, *bfi) {
    a := a_.Clone()
    b := b_.Clone()

    x := newBFI64(0)
    last_x := newBFI64(1)
    y := newBFI64(1)
    last_y := newBFI64(0)

    tmp := newBFI()
    quot := newBFI()

    for b.v.Sign() > 0 {
        quot.Div(a, b)

        // a, b = b, a % b
        tmp.Mod(a, b) // // tmp = a % b
        a.Set(b)      // a = b
        b.Set(tmp)    // b = tmp

        // x, last_x = last_x - quot * x, x
        tmp.Add(last_x, tmp.Mul(x, quot)) // tmp = last_x - quot * x
        last_x.Set(x)                     // last_x = x
        x.Set(tmp)                        // x = tmp

        // y, last_y = last_y - quot * y, y
        tmp.Add(last_y, tmp.Mul(y, quot)) // tmp = last_y - quot * y
        last_y.Set(y)                     // last_y = y
        y.Set(tmp)                        // y = tmp
    }

    return last_x, last_y
}

func _bf_div(a, b *bfi) (*bfi, *bfi) {
    r := a.CloneBigInt()
    q := new(big.Int)

    rlen := a.BitLen()
    blen := b.BitLen()

    // sweeper = 1 << (rlen-1)
    sweeper := new(big.Int).Lsh(one, uint(rlen-1))

    tmp := new(big.Int)

    for rlen >= blen {
        // shift = rlen - blen
        shift := uint(rlen - blen)
        // q |= 1 << shift
        q.Or(q, tmp.Lsh(one, shift))
        // r ^= b << shift
        r.Xor(r, tmp.Lsh(b.v, shift))

        // if r == 0: break #great, evenly divisible
        if r.Sign() == 0 {
            break
        }

        // while r and not sweeper & r:
        for r.Sign() != 0 && tmp.And(sweeper, r).Sign() == 0 {
            //sweeper >>= 1
            sweeper.Rsh(sweeper, 1)
            // rlen -= 1
            rlen--
        }
    }

    return wrapBFI(q), wrapBFI(r)
}
