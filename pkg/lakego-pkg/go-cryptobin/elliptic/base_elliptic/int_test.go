package base_elliptic

import (
    "testing"
)

func Test_bifint_Add(t *testing.T) {
    for idx, tc := range testCases_bfi {
        r := newBFI().Add(tc.arg1, tc.arg2)

        if r.Cmp(tc.add) != 0 {
            t.Errorf("%d: invaild result", idx)
        }
    }
}

func Test_bifint_Mul(t *testing.T) {
    for idx, tc := range testCases_bfi {
        r := newBFI().Mul(tc.arg1, tc.arg2)

        if r.Cmp(tc.mul) != 0 {
            t.Errorf("%d: invaild result", idx)
        }
    }
}

func Test_bifint_Mod(t *testing.T) {
    for idx, tc := range testCases_bfi {
        r := newBFI().Mod(tc.arg1, tc.arg2)

        if r.Cmp(tc.mod) != 0 {
            t.Errorf("%d: invaild result", idx)
        }
    }
}

func Test_bifint_Div(t *testing.T) {
    for idx, tc := range testCases_bfi {
        r := newBFI().Div(tc.arg1, tc.arg2)

        if r.Cmp(tc.div) != 0 {
            t.Errorf("%d: invaild result", idx)
        }
    }
}

func Test_bifint_DivMod(t *testing.T) {
    for idx, tc := range testCases_bfi {
        r := newBFI().DivMod(tc.arg1, tc.arg2, tc.arg3)

        if r.Cmp(tc.divMod) != 0 {
            t.Errorf("%d: invaild result", idx)
        }
    }
}

var (
    testCases_bfi = []struct {
        arg1 *bfi
        arg2 *bfi
        arg3 *bfi

        add    *bfi
        mul    *bfi
        mod    *bfi
        div    *bfi
        divMod *bfi
    }{
        {
            arg1:   wrapBFI(HI(`4cffb0777d6dab9b28ac2dc6514ca8abbb3639fcbd910e2f2de0b25fef6b`)),
            arg2:   wrapBFI(HI(`00fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b`)),
            arg3:   wrapBFI(HI(`01006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052`)),
            add:    wrapBFI(HI(`4c0579a8b6c12888938d1437ea39f744de8a00e336a7f6d7c693c3a2bae0`)),
            mul:    wrapBFI(HI(`3ad962c3abc20228801343ee994f6072ce29f57907db5f5e7258a9e54dad04c756838ed63490f7a712a75e08a82a703d2ee98616fe01e768994865`)),
            mod:    wrapBFI(HI(`7f7c4331685480794c0f9f3a9405d9345b593cd30a3b1614c05d884510`)),
            div:    wrapBFI(HI(`d1`)),
            divMod: wrapBFI(HI(`0x33fe52b13455aaa277153de8131aae871e7566ac4ede57bce25765c11d7b45f573e8a2051b2b8917349954a6c51886c2b611ab0db1896e1a87291d`)),
        },
    }
)
