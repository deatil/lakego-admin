package x962

import (
    "sync"

    "github.com/deatil/go-cryptobin/elliptic/base_elliptic"
)

var initonce sync.Once

var (
    c2pnb176w1 base_elliptic.Curve
    c2pnb163v1 base_elliptic.Curve
    c2pnb163v2 base_elliptic.Curve
    c2pnb163v3 base_elliptic.Curve
    c2pnb208w1 base_elliptic.Curve
    c2tnb191v3 base_elliptic.Curve
    c2tnb191v2 base_elliptic.Curve
    c2tnb191v1 base_elliptic.Curve
    c2tnb239v3 base_elliptic.Curve
    c2tnb239v2 base_elliptic.Curve
    c2tnb239v1 base_elliptic.Curve
    c2pnb272w1 base_elliptic.Curve
    c2pnb304w1 base_elliptic.Curve
    c2pnb368w1 base_elliptic.Curve
    c2tnb359v1 base_elliptic.Curve
    c2tnb431r1 base_elliptic.Curve
    c2onb191v4 base_elliptic.Curve
    c2onb191v5 base_elliptic.Curve
    c2onb239v4 base_elliptic.Curve
    c2onb239v5 base_elliptic.Curve
)

func initAll() {
    c2pnb176w1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2pnb176w1",
            BitSize: 176,
            F:       base_elliptic.F(176, 43, 2, 1, 0),
            A:       base_elliptic.HI("0xe4e6db2995065c407d9d39b8d0967b96704ba8e9c90b"),
            B:       base_elliptic.HI("0x5dda470abe6414de8ec133ae28e9bbd7fcec0ae0fff2"),
            Gx:      base_elliptic.HI("0x8d16c2866798b600f9f08bb4a8e860f3298ce04a5798"),
            Gy:      base_elliptic.HI("0x6fa4539c2dadddd6bab5167d61b436e1d92bb16a562c"),
            N:       base_elliptic.HI("0x010092537397eca4f6145799d62b0a19ce06fe26ad"),
            H:       0xff6e,
        },
    )

    c2pnb163v1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2pnb163v1",
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

    c2pnb163v2 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2pnb163v2",
            BitSize: 163,
            F:       base_elliptic.F(163, 8, 2, 1, 0),
            A:       base_elliptic.HI("0x0108b39e77c4b108bed981ed0e890e117c511cf072"),
            B:       base_elliptic.HI("0x0667aceb38af4e488c407433ffae4f1c811638df20"),
            Gx:      base_elliptic.HI("0x0024266e4eb5106d0a964d92c4860e2671db9b6cc5"),
            Gy:      base_elliptic.HI("0x079f684ddf6684c5cd258b3890021b2386dfd19fc5"),
            N:       base_elliptic.HI("0x03fffffffffffffffffffdf64de1151adbb78f10a7"),
            H:       0x2,
        },
    )

    c2pnb163v3 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2pnb163v3",
            BitSize: 163,
            F:       base_elliptic.F(163, 8, 2, 1, 0),
            A:       base_elliptic.HI("0x07a526c63d3e25a256a007699f5447e32ae456b50e"),
            B:       base_elliptic.HI("0x03f7061798eb99e238fd6f1bf95b48feeb4854252b"),
            Gx:      base_elliptic.HI("0x2f9f87b7c574d0bdecf8a22e6524775f98cdebdcb"),
            Gy:      base_elliptic.HI("0x5b935590c155e17ea48eb3ff3718b893df59a05d0"),
            N:       base_elliptic.HI("0x03fffffffffffffffffffe1aee140f110aff961309"),
            H:       0x2,
        },
    )

    c2pnb208w1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2pnb208w1",
            BitSize: 208,
            F:       base_elliptic.F(208, 83, 2, 1, 0),
            A:       base_elliptic.HI("0x0"),
            B:       base_elliptic.HI("0xc8619ed45a62e6212e1160349e2bfa844439fafc2a3fd1638f9e"),
            Gx:      base_elliptic.HI("0x89fdfbe4abe193df9559ecf07ac0ce78554e2784eb8c1ed1a57a"),
            Gy:      base_elliptic.HI("0x0f55b51a06e78e9ac38a035ff520d8b01781beb1a6bb08617de3"),
            N:       base_elliptic.HI("0x0101baf95c9723c57b6c21da2eff2d5ed588bdd5717e212f9d"),
            H:       0xfe48,
        },
    )

    c2tnb191v3 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2tnb191v3",
            BitSize: 191,
            F:       base_elliptic.F(191, 9, 0),
            A:       base_elliptic.HI("0x6c01074756099122221056911c77d77e77a777e7e7e77fcb"),
            B:       base_elliptic.HI("0x71fe1af926cf847989efef8db459f66394d90f32ad3f15e8"),
            Gx:      base_elliptic.HI("0x375d4ce24fde434489de8746e71786015009e66e38a926dd"),
            Gy:      base_elliptic.HI("0x545a39176196575d985999366e6ad34ce0a77cd7127b06be"),
            N:       base_elliptic.HI("0x155555555555555555555555610c0b196812bfb6288a3ea3"),
            H:       0x6,
        },
    )

    c2tnb191v2 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2tnb191v2",
            BitSize: 191,
            F:       base_elliptic.F(191, 9, 0),
            A:       base_elliptic.HI("0x401028774d7777c7b7666d1366ea432071274f89ff01e718"),
            B:       base_elliptic.HI("0x0620048d28bcbd03b6249c99182b7c8cd19700c362c46a01"),
            Gx:      base_elliptic.HI("0x3809b2b7cc1b28cc5a87926aad83fd28789e81e2c9e3bf10"),
            Gy:      base_elliptic.HI("0x17434386626d14f3dbf01760d9213a3e1cf37aec437d668a"),
            N:       base_elliptic.HI("0x20000000000000000000000050508cb89f652824e06b8173"),
            H:       0x4,
        },
    )

    c2tnb191v1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2tnb191v1",
            BitSize: 191,
            F:       base_elliptic.F(191, 9, 0),
            A:       base_elliptic.HI("0x2866537b676752636a68f56554e12640276b649ef7526267"),
            B:       base_elliptic.HI("0x2e45ef571f00786f67b0081b9495a3d95462f5de0aa185ec"),
            Gx:      base_elliptic.HI("0x36b3daf8a23206f9c4f299d7b21a9c369137f2c84ae1aa0d"),
            Gy:      base_elliptic.HI("0x765be73433b3f95e332932e70ea245ca2418ea0ef98018fb"),
            N:       base_elliptic.HI("0x40000000000000000000000004a20e90c39067c893bbb9a5"),
            H:       0x2,
        },
    )

    c2tnb239v3 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2tnb239v3",
            BitSize: 239,
            F:       base_elliptic.F(239, 36, 0),
            A:       base_elliptic.HI("0x01238774666a67766d6676f778e676b66999176666e687666d8766c66a9f"),
            B:       base_elliptic.HI("0x6a941977ba9f6a435199acfc51067ed587f519c5ecb541b8e44111de1d40"),
            Gx:      base_elliptic.HI("0x70f6e9d04d289c4e89913ce3530bfde903977d42b146d539bf1bde4e9c92"),
            Gy:      base_elliptic.HI("0x2e5a0eaf6e5e1305b9004dce5c0ed7fe59a35608f33837c816d80b79f461"),
            N:       base_elliptic.HI("0x0cccccccccccccccccccccccccccccac4912d2d9df903ef9888b8a0e4cff"),
            H:       0x0a,
        },
    )

    c2tnb239v2 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2tnb239v2",
            BitSize: 239,
            F:       base_elliptic.F(239, 36, 0),
            A:       base_elliptic.HI("0x4230017757a767fae42398569b746325d45313af0766266479b75654e65f"),
            B:       base_elliptic.HI("0x5037ea654196cff0cd82b2c14a2fcf2e3ff8775285b545722f03eacdb74b"),
            Gx:      base_elliptic.HI("0x28f9d04e900069c8dc47a08534fe76d2b900b7d7ef31f5709f200c4ca205"),
            Gy:      base_elliptic.HI("0x5667334c45aff3b5a03bad9dd75e2c71a99362567d5453f7fa6e227ec833"),
            N:       base_elliptic.HI("0x1555555555555555555555555555553c6f2885259c31e3fcdf154624522d"),
            H:       0x6,
        },
    )

    c2tnb239v1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2tnb239v1",
            BitSize: 239,
            F:       base_elliptic.F(239, 36, 0),
            A:       base_elliptic.HI("0x32010857077c5431123a46b808906756f543423e8d27877578125778ac76"),
            B:       base_elliptic.HI("0x790408f2eedaf392b012edefb3392f30f4327c0ca3f31fc383c422aa8c16"),
            Gx:      base_elliptic.HI("0x57927098fa932e7c0a96d3fd5b706ef7e5f5c156e16b7e7c86038552e91d"),
            Gy:      base_elliptic.HI("0x61d8ee5077c33fecf6f1a16b268de469c3c7744ea9a971649fc7a9616305"),
            N:       base_elliptic.HI("0x2000000000000000000000000000000f4d42ffe1492a4993f1cad666e447"),
            H:       0x4,
        },
    )

    c2pnb272w1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2pnb272w1",
            BitSize: 272,
            F:       base_elliptic.F(272, 56, 3, 1, 0),
            A:       base_elliptic.HI("0x91a091f03b5fba4ab2ccf49c4edd220fb028712d42be752b2c40094dbacdb586fb20"),
            B:       base_elliptic.HI("0x7167efc92bb2e3ce7c8aaaff34e12a9c557003d7c73a6faf003f99f6cc8482e540f7"),
            Gx:      base_elliptic.HI("0x6108babb2ceebcf787058a056cbe0cfe622d7723a289e08a07ae13ef0d10d171dd8d"),
            Gy:      base_elliptic.HI("0x10c7695716851eef6ba7f6872e6142fbd241b830ff5efcaceccab05e02005dde9d23"),
            N:       base_elliptic.HI("0x0100faf51354e0e39e4892df6e319c72c8161603fa45aa7b998a167b8f1e629521"),
            H:       0xff06,
        },
    )

    c2pnb304w1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2pnb304w1",
            BitSize: 304,
            F:       base_elliptic.F(304, 11, 2, 1, 0),
            A:       base_elliptic.HI("0xfd0d693149a118f651e6dce6802085377e5f882d1b510b44160074c1288078365a0396c8e681"),
            B:       base_elliptic.HI("0xbddb97e555a50a908e43b01c798ea5daa6788f1ea2794efcf57166b8c14039601e55827340be"),
            Gx:      base_elliptic.HI("0x197b07845e9be2d96adb0f5f3c7f2cffbd7a3eb8b6fec35c7fd67f26ddf6285a644f740a2614"),
            Gy:      base_elliptic.HI("0xe19fbeb76e0da171517ecf401b50289bf014103288527a9b416a105e80260b549fdc1b92c03b"),
            N:       base_elliptic.HI("0x0101d556572aabac800101d556572aabac8001022d5c91dd173f8fb561da6899164443051d"),
            H:       0xfe2e,
        },
    )

    c2pnb368w1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2pnb368w1",
            BitSize: 368,
            F:       base_elliptic.F(368, 85, 2, 1, 0),
            A:       base_elliptic.HI("0xe0d2ee25095206f5e2a4f9ed229f1f256e79a0e2b455970d8d0d865bd94778c576d62f0ab7519ccd2a1a906ae30d"),
            B:       base_elliptic.HI("0xfc1217d4320a90452c760a58edcd30c8dd069b3c34453837a34ed50cb54917e1c2112d84d164f444f8f74786046a"),
            Gx:      base_elliptic.HI("0x1085e2755381dccce3c1557afa10c2f0c0c2825646c5b34a394cbcfa8bc16b22e7e789e927be216f02e1fb136a5f"),
            Gy:      base_elliptic.HI("0x7b3eb1bddcba62d5d8b2059b525797fc73822c59059c623a45ff3843cee8f87cd1855adaa81e2a0750b80fda2310"),
            N:       base_elliptic.HI("0x010090512da9af72b08349d98a5dd4c7b0532eca51ce03e2d10f3b7ac579bd87e909ae40a6f131e9cfce5bd967"),
            H:       0xff70,
        },
    )

    c2tnb359v1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2tnb359v1",
            BitSize: 359,
            F:       base_elliptic.F(359, 68, 0),
            A:       base_elliptic.HI("0x5667676a654b20754f356ea92017d946567c46675556f19556a04616b567d223a5e05656fb549016a96656a557"),
            B:       base_elliptic.HI("0x2472e2d0197c49363f1fe7f5b6db075d52b6947d135d8ca445805d39bc345626089687742b6329e70680231988"),
            Gx:      base_elliptic.HI("0x3c258ef3047767e7ede0f1fdaa79daee3841366a132e163aced4ed2401df9c6bdcde98e8e707c07a2239b1b097"),
            Gy:      base_elliptic.HI("0x53d7e08529547048121e9c95f3791dd804963948f34fae7bf44ea82365dc7868fe57e4ae2de211305a407104bd"),
            N:       base_elliptic.HI("0x01af286bca1af286bca1af286bca1af286bca1af286bc9fb8f6b85c556892c20a7eb964fe7719e74f490758d3b"),
            H:       0x4c,
        },
    )

    c2tnb431r1 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2tnb431r1",
            BitSize: 431,
            F:       base_elliptic.F(431, 120, 0),
            A:       base_elliptic.HI("0x1a827ef00dd6fc0e234caf046c6a5d8a85395b236cc4ad2cf32a0cadbdc9ddf620b0eb9906d0957f6c6feacd615468df104de296cd8f"),
            B:       base_elliptic.HI("0x10d9b4a3d9047d8b154359abfb1b7f5485b04ceb868237ddc9deda982a679a5a919b626d4e50a8dd731b107a9962381fb5d807bf2618"),
            Gx:      base_elliptic.HI("0x120fc05d3c67a99de161d2f4092622feca701be4f50f4758714e8a87bbf2a658ef8c21e7c5efe965361f6c2999c0c247b0dbd70ce6b7"),
            Gy:      base_elliptic.HI("0x20d0af8903a96f8d5fa2c255745d3c451b302c9346d9b7e485e7bce41f6b591f3e8f6addcbb0bc4c2f947a7de1a89b625d6a598b3760"),
            N:       base_elliptic.HI("0x0340340340340340340340340340340340340340340340340340340323c313fab50589703b5ec68d3587fec60d161cc149c1ad4a91"),
            H:       0x2760,
        },
    )

    c2onb191v4 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2onb191v4",
            BitSize: 191,
            F:       base_elliptic.F(191, 190, 188, 184, 176, 160, 128, 64, 63, 62, 60, 56, 48, 32, 0),
            A:       base_elliptic.HI("0x65903E04E1E4924253E26A3C9AC28C758BD8184A3FB680E8"),
            B:       base_elliptic.HI("0x54678621B190CFCE282ADE219D5B3A065E3F4B3FFDEBB29B"),
            Gx:      base_elliptic.HI("0x025A2C69A32E8638E51CCEFAAD05350A978457CB5FB6DF994A"),
            Gy:      base_elliptic.HI(""),
            N:       base_elliptic.HI("0x4000000000000000000000009CF2D6E3901DAC4C32EEC65D"),
            H:       0x2,
        },
    )

    c2onb191v5 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2onb191v5",
            BitSize: 191,
            F:       base_elliptic.F(191, 190, 188, 184, 176, 160, 128, 64, 63, 62, 60, 56, 48, 32, 0),
            A:       base_elliptic.HI("0x25F8D06C97C822536D469CD5170CDD7BB9F500BD6DB110FB"),
            B:       base_elliptic.HI("0x75FF570E35CA94FB3780C2619D081C17AA59FBD5E591C1C4"),
            Gx:      base_elliptic.HI("0x032A16910E8F6C4B199BE24213857ABC9C992EDFB2471F3C68"),
            Gy:      base_elliptic.HI(""),
            N:       base_elliptic.HI("0x0FFFFFFFFFFFFFFFFFFFFFFFEEB354B7270B2992B7818627"),
            H:       0x8,
        },
    )

    c2onb239v4 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2onb239v4",
            BitSize: 239,
            F:       base_elliptic.F(239, 238, 236, 232, 224, 208, 207, 206, 204, 200, 192, 144, 143, 142, 140, 136, 128, 16, 15, 14, 12, 8, 0),
            A:       base_elliptic.HI("0x182DD45F5D470239B8983FEA47B8B292641C57F9BF84BAECDE8BB3ADCE30"),
            B:       base_elliptic.HI("0x147A9C1D4C2CE9BE5D34EC02797F76667EBAD5A3F93FA2A524BFDE91EF28"),
            Gx:      base_elliptic.HI("0x034912AD657F1D1C6B32EDB9942C95E226B06FB012CD40FDEA0D72197C8104"),
            Gy:      base_elliptic.HI(""),
            N:       base_elliptic.HI("0x200000000000000000000000000000474F7E69F42FE430931D0B455AAE8B"),
            H:       0x04,
        },
    )

    c2onb239v5 = base_elliptic.NewCurve(
        &base_elliptic.CurveParams{
            Name:    "c2onb239v5",
            BitSize: 239,
            F:       base_elliptic.F(239, 238, 236, 232, 224, 208, 207, 206, 204, 200, 192, 144, 143, 142, 140, 136, 128, 16, 15, 14, 12, 8, 0),
            A:       base_elliptic.HI("0x1ECF1B9D28D8017505E17475D3DF2982E243CA5CB5E9F94A3F36124A486E"),
            B:       base_elliptic.HI("0x3EE257250D1A2E66CEF23AA0F25B12388DE8A10FF9554F90AFBAA9A08B6D"),
            Gx:      base_elliptic.HI("0x02193279FC543E9F5F7119189785B9C60B249BE4820BAF6C24BDFA2813F8B8"),
            Gy:      base_elliptic.HI(""),
            N:       base_elliptic.HI("0x1555555555555555555555555555558CF77A5D0589D2A9340D963B7AD703"),
            H:       0x06,
        },
    )
}
