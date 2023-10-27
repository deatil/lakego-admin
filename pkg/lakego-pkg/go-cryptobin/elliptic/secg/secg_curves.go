package secg

import (
    "sync"

    "github.com/deatil/go-cryptobin/elliptic/base_elliptic"
)

var initonce sync.Once

var (
    sect113r1 base_elliptic.Curve
    sect113r2 base_elliptic.Curve
    sect131r1 base_elliptic.Curve
    sect131r2 base_elliptic.Curve
    sect163k1 base_elliptic.Curve
    sect163r1 base_elliptic.Curve
    sect163r2 base_elliptic.Curve
    sect193r1 base_elliptic.Curve
    sect193r2 base_elliptic.Curve
    sect233k1 base_elliptic.Curve
    sect233r1 base_elliptic.Curve
    sect239k1 base_elliptic.Curve
    sect283k1 base_elliptic.Curve
    sect283r1 base_elliptic.Curve
    sect409k1 base_elliptic.Curve
    sect409r1 base_elliptic.Curve
    sect571k1 base_elliptic.Curve
    sect571r1 base_elliptic.Curve
)

func initAll() {
    sect113r1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect113r1",
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

    sect113r2 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect113r2",
            BitSize: 113,
            F:       base_elliptic.F(113, 9, 0),
            A:       base_elliptic.HI("0x00689918dbec7e5a0dd6dfc0aa55c7"),
            B:       base_elliptic.HI("0x0095e9a9ec9b297bd4bf36e059184f"),
            Gx:      base_elliptic.HI("0x01a57a6a7b26ca5ef52fcdb8164797"),
            Gy:      base_elliptic.HI("0x00b3adc94ed1fe674c06e695baba1d"),
            N:       base_elliptic.HI("0x010000000000000108789b2496af93"),
            H:       0x2,
        },
    )

    sect131r1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect131r1",
            BitSize: 131,
            F:       base_elliptic.F(131, 8, 3, 2, 0),
            A:       base_elliptic.HI("0x07a11b09a76b562144418ff3ff8c2570b8"),
            B:       base_elliptic.HI("0x0217c05610884b63b9c6c7291678f9d341"),
            Gx:      base_elliptic.HI("0x0081baf91fdf9833c40f9c181343638399"),
            Gy:      base_elliptic.HI("0x078c6e7ea38c001f73c8134b1b4ef9e150"),
            N:       base_elliptic.HI("0x0400000000000000023123953a9464b54d"),
            H:       0x2,
        },
    )

    sect131r2 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect131r2",
            BitSize: 131,
            F:       base_elliptic.F(131, 8, 3, 2, 0),
            A:       base_elliptic.HI("0x03e5a88919d7cafcbf415f07c2176573b2"),
            B:       base_elliptic.HI("0x04b8266a46c55657ac734ce38f018f2192"),
            Gx:      base_elliptic.HI("0x0356dcd8f2f95031ad652d23951bb366a8"),
            Gy:      base_elliptic.HI("0x0648f06d867940a5366d9e265de9eb240f"),
            N:       base_elliptic.HI("0x0400000000000000016954a233049ba98f"),
            H:       0x2,
        },
    )

    sect163k1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect163k1",
            BitSize: 163,
            F:       base_elliptic.F(163, 7, 6, 3, 0),
            A:       base_elliptic.HI("0x000000000000000000000000000000000000000001"),
            B:       base_elliptic.HI("0x000000000000000000000000000000000000000001"),
            Gx:      base_elliptic.HI("0x02fe13c0537bbc11acaa07d793de4e6d5e5c94eee8"),
            Gy:      base_elliptic.HI("0x0289070fb05d38ff58321f2e800536d538ccdaa3d9"),
            N:       base_elliptic.HI("0x04000000000000000000020108a2e0cc0d99f8a5ef"),
            H:       0x2,
        },
    )

    sect163r1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect163r1",
            BitSize: 163,
            F:       base_elliptic.F(163, 7, 6, 3, 0),
            A:       base_elliptic.HI("0x07b6882caaefa84f9554ff8428bd88e246d2782ae2"),
            B:       base_elliptic.HI("0x0713612dcddcb40aab946bda29ca91f73af958afd9"),
            Gx:      base_elliptic.HI("0x0369979697ab43897789566789567f787a7876a654"),
            Gy:      base_elliptic.HI("0x00435edb42efafb2989d51fefce3c80988f41ff883"),
            N:       base_elliptic.HI("0x03ffffffffffffffffffff48aab689c29ca710279b"),
            H:       0x2,
        },
    )

    sect163r2 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect163r2",
            BitSize: 163,
            F:       base_elliptic.F(163, 7, 6, 3, 0),
            A:       base_elliptic.HI("0x000000000000000000000000000000000000000001"),
            B:       base_elliptic.HI("0x020a601907b8c953ca1481eb10512f78744a3205fd"),
            Gx:      base_elliptic.HI("0x03f0eba16286a2d57ea0991168d4994637e8343e36"),
            Gy:      base_elliptic.HI("0x00d51fbc6c71a0094fa2cdd545b11c5c0c797324f1"),
            N:       base_elliptic.HI("0x040000000000000000000292fe77e70c12a4234c33"),
            H:       0x2,
        },
    )

    sect193r1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect193r1",
            BitSize: 193,
            F:       base_elliptic.F(193, 15, 0),
            A:       base_elliptic.HI("0x0017858feb7a98975169e171f77b4087de098ac8a911df7b01"),
            B:       base_elliptic.HI("0x00fdfb49bfe6c3a89facadaa7a1e5bbc7cc1c2e5d831478814"),
            Gx:      base_elliptic.HI("0x01f481bc5f0ff84a74ad6cdf6fdef4bf6179625372d8c0c5e1"),
            Gy:      base_elliptic.HI("0x0025e399f2903712ccf3ea9e3a1ad17fb0b3201b6af7ce1b05"),
            N:       base_elliptic.HI("0x01000000000000000000000000c7f34a778f443acc920eba49"),
            H:       0x2,
        },
    )

    sect193r2 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect193r2",
            BitSize: 193,
            F:       base_elliptic.F(193, 15, 0),
            A:       base_elliptic.HI("0x0163f35a5137c2ce3ea6ed8667190b0bc43ecd69977702709b"),
            B:       base_elliptic.HI("0x00c9bb9e8927d4d64c377e2ab2856a5b16e3efb7f61d4316ae"),
            Gx:      base_elliptic.HI("0x00d9b67d192e0367c803f39e1a7e82ca14a651350aae617e8f"),
            Gy:      base_elliptic.HI("0x01ce94335607c304ac29e7defbd9ca01f596f927224cdecf6c"),
            N:       base_elliptic.HI("0x010000000000000000000000015aab561b005413ccd4ee99d5"),
            H:       0x2,
        },
    )

    sect233k1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect233k1",
            BitSize: 233,
            F:       base_elliptic.F(233, 74, 0),
            A:       base_elliptic.HI("0x000000000000000000000000000000000000000000000000000000000000"),
            B:       base_elliptic.HI("0x000000000000000000000000000000000000000000000000000000000001"),
            Gx:      base_elliptic.HI("0x017232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126"),
            Gy:      base_elliptic.HI("0x01db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3"),
            N:       base_elliptic.HI("0x8000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf"),
            H:       0x4,
        },
    )

    sect233r1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect233r1",
            BitSize: 233,
            F:       base_elliptic.F(233, 74, 0),
            A:       base_elliptic.HI("0x000000000000000000000000000000000000000000000000000000000001"),
            B:       base_elliptic.HI("0x0066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad"),
            Gx:      base_elliptic.HI("0x00fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b"),
            Gy:      base_elliptic.HI("0x01006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052"),
            N:       base_elliptic.HI("0x01000000000000000000000000000013e974e72f8a6922031d2603cfe0d7"),
            H:       0x2,
        },
    )

    sect239k1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect239k1",
            BitSize: 239,
            F:       base_elliptic.F(239, 158, 0),
            A:       base_elliptic.HI("0x000000000000000000000000000000000000000000000000000000000000"),
            B:       base_elliptic.HI("0x000000000000000000000000000000000000000000000000000000000001"),
            Gx:      base_elliptic.HI("0x29a0b6a887a983e9730988a68727a8b2d126c44cc2cc7b2a6555193035dc"),
            Gy:      base_elliptic.HI("0x76310804f12e549bdb011c103089e73510acb275fc312a5dc6b76553f0ca"),
            N:       base_elliptic.HI("0x2000000000000000000000000000005a79fec67cb6e91f1c1da800e478a5"),
            H:       0x4,
        },
    )

    sect283k1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect283k1",
            BitSize: 283,
            F:       base_elliptic.F(283, 12, 7, 5, 0),
            A:       base_elliptic.HI("0x000000000000000000000000000000000000000000000000000000000000000000000000"),
            B:       base_elliptic.HI("0x000000000000000000000000000000000000000000000000000000000000000000000001"),
            Gx:      base_elliptic.HI("0x0503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836"),
            Gy:      base_elliptic.HI("0x01ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259"),
            N:       base_elliptic.HI("0x01ffffffffffffffffffffffffffffffffffe9ae2ed07577265dff7f94451e061e163c61"),
            H:       0x4,
        },
    )

    sect283r1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect283r1",
            BitSize: 283,
            F:       base_elliptic.F(283, 12, 7, 5, 0),
            A:       base_elliptic.HI("0x000000000000000000000000000000000000000000000000000000000000000000000001"),
            B:       base_elliptic.HI("0x027b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5"),
            Gx:      base_elliptic.HI("0x05f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053"),
            Gy:      base_elliptic.HI("0x03676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4"),
            N:       base_elliptic.HI("0x03ffffffffffffffffffffffffffffffffffef90399660fc938a90165b042a7cefadb307"),
            H:       0x2,
        },
    )

    sect409k1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect409k1",
            BitSize: 409,
            F:       base_elliptic.F(409, 87, 0),
            A:       base_elliptic.HI("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            B:       base_elliptic.HI("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"),
            Gx:      base_elliptic.HI("0x0060f05f658f49c1ad3ab1890f7184210efd0987e307c84c27accfb8f9f67cc2c460189eb5aaaa62ee222eb1b35540cfe9023746"),
            Gy:      base_elliptic.HI("0x01e369050b7c4e42acba1dacbf04299c3460782f918ea427e6325165e9ea10e3da5f6c42e9c55215aa9ca27a5863ec48d8e0286b"),
            N:       base_elliptic.HI("0x7ffffffffffffffffffffffffffffffffffffffffffffffffffe5f83b2d4ea20400ec4557d5ed3e3e7ca5b4b5c83b8e01e5fcf"),
            H:       0x4,
        },
    )

    sect409r1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect409r1",
            BitSize: 409,
            F:       base_elliptic.F(409, 87, 0),
            A:       base_elliptic.HI("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"),
            B:       base_elliptic.HI("0x0021a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f"),
            Gx:      base_elliptic.HI("0x015d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7"),
            Gy:      base_elliptic.HI("0x0061b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706"),
            N:       base_elliptic.HI("0x010000000000000000000000000000000000000000000000000001e2aad6a612f33307be5fa47c3c9e052f838164cd37d9a21173"),
            H:       0x2,
        },
    )

    sect571k1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect571k1",
            BitSize: 571,
            F:       base_elliptic.F(571, 10, 5, 2, 0),
            A:       base_elliptic.HI("0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            B:       base_elliptic.HI("0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"),
            Gx:      base_elliptic.HI("0x026eb7a859923fbc82189631f8103fe4ac9ca2970012d5d46024804801841ca44370958493b205e647da304db4ceb08cbbd1ba39494776fb988b47174dca88c7e2945283a01c8972"),
            Gy:      base_elliptic.HI("0x0349dc807f4fbf374f4aeade3bca95314dd58cec9f307a54ffc61efc006d8a2c9d4979c0ac44aea74fbebbb9f772aedcb620b01a7ba7af1b320430c8591984f601cd4c143ef1c7a3"),
            N:       base_elliptic.HI("0x020000000000000000000000000000000000000000000000000000000000000000000000131850e1f19a63e4b391a8db917f4138b630d84be5d639381e91deb45cfe778f637c1001"),
            H:       0x4,
        },
    )

    sect571r1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "sect571r1",
            BitSize: 571,
            F:       base_elliptic.F(571, 10, 5, 2, 0),
            A:       base_elliptic.HI("0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"),
            B:       base_elliptic.HI("0x02f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a"),
            Gx:      base_elliptic.HI("0x0303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19"),
            Gy:      base_elliptic.HI("0x037bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b"),
            N:       base_elliptic.HI("0x03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe661ce18ff55987308059b186823851ec7dd9ca1161de93d5174d66e8382e9bb2fe84e47"),
            H:       0x2,
        },
    )
}
