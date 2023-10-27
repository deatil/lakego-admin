package base_elliptic

import (
    "math/big"
)

var (
    b233 = &curve{
        params: &CurveParams{
            Name:    "B-233",
            BitSize: 233,
            F:       F(233, 74, 0),
            A:       HI("0x000000000000000000000000000000000000000000000000000000000001"),
            B:       HI("0x0066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad"),
            Gx:      HI("0x00fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b"),
            Gy:      HI("0x01006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052"),
            N:       HI("0x1000000000000000000000000000013e974e72f8a6922031d2603cfe0d7"),
            H:       0x2,
        },
    }
)

type internalTestcase struct {
    x1, y1 *big.Int
    x2, y2 *big.Int
    x, y   *big.Int
}
