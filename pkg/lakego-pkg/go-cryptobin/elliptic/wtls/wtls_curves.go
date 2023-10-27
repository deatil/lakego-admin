package wtls

import (
    "sync"

    "github.com/deatil/go-cryptobin/elliptic/base_elliptic"
)

var initonce sync.Once

var (
    wapwsgidmecidwtls1  base_elliptic.Curve
    wapwsgidmecidwtls3  base_elliptic.Curve
    wapwsgidmecidwtls4  base_elliptic.Curve
    wapwsgidmecidwtls5  base_elliptic.Curve
    wapwsgidmecidwtls10 base_elliptic.Curve
    wapwsgidmecidwtls11 base_elliptic.Curve
)

func initAll() {
    wapwsgidmecidwtls1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "wap-wsg-idm-ecid-wtls1",
            BitSize: 113,
            F:       base_elliptic.F(113, 9, 0),
            A:       base_elliptic.HI("0x1"),
            B:       base_elliptic.HI("0x1"),
            Gx:      base_elliptic.HI("0x01667979a40ba497e5d5c270780617"),
            Gy:      base_elliptic.HI("0x00f44b4af1ecc2630e08785cebcc15"),
            N:       base_elliptic.HI("0x00fffffffffffffffdbf91af6dea73"),
            H:       0x2,
        },
    )

    wapwsgidmecidwtls3 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "wap-wsg-idm-ecid-wtls3",
            BitSize: 163,
            F:       base_elliptic.F(163, 7, 6, 3, 0),
            A:       base_elliptic.HI("0x1"),
            B:       base_elliptic.HI("0x1"),
            Gx:      base_elliptic.HI("0x02fe13c0537bbc11acaa07d793de4e6d5e5c94eee8"),
            Gy:      base_elliptic.HI("0x0289070fb05d38ff58321f2e800536d538ccdaa3d9"),
            N:       base_elliptic.HI("0x04000000000000000000020108a2e0cc0d99f8a5ef"),
            H:       0x2,
        },
    )

    wapwsgidmecidwtls4 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "wap-wsg-idm-ecid-wtls4",
            BitSize: 113,
            F:       base_elliptic.F(113, 9, 0),
            A:       base_elliptic.HI("0x003088250ca6e7c7fe649ce85820f7"),
            B:       base_elliptic.HI("0x00e8bee4d3e2260744188be0e9c723"),
            Gx:      base_elliptic.HI("0x009d73616f35f4ab1407d73562c10f"),
            Gy:      base_elliptic.HI("0x00a52830277958ee84d1315ed31886"),
            N:       base_elliptic.HI("0x0100000000000000d9ccec8a39e56f"),
            H:       0x2,
        },
    )

    wapwsgidmecidwtls5 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "wap-wsg-idm-ecid-wtls5",
            BitSize: 163,
            F:       base_elliptic.F(163, 8, 2, 1, 0),
            A:       base_elliptic.HI("0x072546b5435234a422e0789675f432c89435de5242"),
            B:       base_elliptic.HI("0x00c9517d06d5240d3cff38c74b20b6cd4d6f9dd4d9"),
            Gx:      base_elliptic.HI("0x07af69989546103d79329fcc3d74880f33bbe803cb"),
            Gy:      base_elliptic.HI("0x01ec23211b5966adea1d3f87f7ea5848aef0b7ca9f"),
            N:       base_elliptic.HI("0x0400000000000000000001e60fc8821cc74daeafc1"),
            H:       0x2,
        },
    )

    wapwsgidmecidwtls10 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "wap-wsg-idm-ecid-wtls10",
            BitSize: 233,
            F:       base_elliptic.F(233, 74, 0),
            A:       base_elliptic.HI("0x0"),
            B:       base_elliptic.HI("0x1"),
            Gx:      base_elliptic.HI("0x017232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126"),
            Gy:      base_elliptic.HI("0x01db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3"),
            N:       base_elliptic.HI("0x8000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf"),
            H:       0x4,
        },
    )

    wapwsgidmecidwtls11 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "wap-wsg-idm-ecid-wtls11",
            BitSize: 233,
            F:       base_elliptic.F(233, 74, 0),
            A:       base_elliptic.HI("0x1"),
            B:       base_elliptic.HI("0x0066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad"),
            Gx:      base_elliptic.HI("0x00fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b"),
            Gy:      base_elliptic.HI("0x01006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052"),
            N:       base_elliptic.HI("0x01000000000000000000000000000013e974e72f8a6922031d2603cfe0d7"),
            H:       0x2,
        },
    )
}
