package curve256k1

import (
    "testing"
)

func TestEqual(t *testing.T) {
    tests := []struct {
        x1, y1, z1 string
        x2, y2, z2 string
        eq         bool
    }{
        {
            x1: "0000000000000000000000000000000000000000000000000000000000000000",
            y1: "0000000000000000000000000000000000000000000000000000000000000000",
            z1: "0000000000000000000000000000000000000000000000000000000000000000",
            x2: "0000000000000000000000000000000000000000000000000000000000000000",
            y2: "0000000000000000000000000000000000000000000000000000000000000000",
            z2: "0000000000000000000000000000000000000000000000000000000000000000",
            eq: true,
        },
        {
            x1: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y1: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z1: "0000000000000000000000000000000000000000000000000000000000000001",
            x2: "0000000000000000000000000000000000000000000000000000000000000000",
            y2: "0000000000000000000000000000000000000000000000000000000000000000",
            z2: "0000000000000000000000000000000000000000000000000000000000000000",
            eq: false,
        },
        {
            x1: "0000000000000000000000000000000000000000000000000000000000000000",
            y1: "0000000000000000000000000000000000000000000000000000000000000000",
            z1: "0000000000000000000000000000000000000000000000000000000000000000",
            x2: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y2: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z2: "0000000000000000000000000000000000000000000000000000000000000001",
            eq: false,
        },
        {
            x1: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y1: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z1: "0000000000000000000000000000000000000000000000000000000000000001",
            x2: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y2: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z2: "0000000000000000000000000000000000000000000000000000000000000001",
            eq: true,
        },
        {
            x1: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y1: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z1: "0000000000000000000000000000000000000000000000000000000000000001",
            x2: "1e6c40c6c5babb5c9fe547c3eb7baf26a54024a187f899a1a68b95f9bb6a5685",
            y2: "7a72ea58024ebd536c38cf3200d248782b06e7aea94a97359a5d1cd85b6cee89",
            z2: "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe18",
            eq: true,
        },
    }

    for _, tc := range tests {
        var p1, p2 PointJacobian
        p1.x.Set(hex2element(tc.x1))
        p1.y.Set(hex2element(tc.y1))
        p1.z.Set(hex2element(tc.z1))

        p2.x.Set(hex2element(tc.x2))
        p2.y.Set(hex2element(tc.y2))
        p2.z.Set(hex2element(tc.z2))

        var v PointJacobian
        v.Add(&p1, &p2)

        if (p1.Equal(&p2) != 0) != tc.eq {
            var a, b Point
            a.FromJacobian(&p1)
            b.FromJacobian(&p2)
            t.Errorf(
                "(%x, %x) == (%x, %x) should be %t, but got not",
                a.x.Bytes(), a.y.Bytes(),
                b.x.Bytes(), b.y.Bytes(),
                tc.eq,
            )
        }
    }
}

func TestAdd(t *testing.T) {
    tests := []struct {
        x1, y1, z1 string
        x2, y2, z2 string
        x3, y3, z3 string
    }{
        {
            x1: "0000000000000000000000000000000000000000000000000000000000000000",
            y1: "0000000000000000000000000000000000000000000000000000000000000000",
            z1: "0000000000000000000000000000000000000000000000000000000000000000",
            x2: "0000000000000000000000000000000000000000000000000000000000000000",
            y2: "0000000000000000000000000000000000000000000000000000000000000000",
            z2: "0000000000000000000000000000000000000000000000000000000000000000",
            x3: "0000000000000000000000000000000000000000000000000000000000000000",
            y3: "0000000000000000000000000000000000000000000000000000000000000000",
            z3: "0000000000000000000000000000000000000000000000000000000000000000",
        },
        {
            x1: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y1: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z1: "0000000000000000000000000000000000000000000000000000000000000001",
            x2: "0000000000000000000000000000000000000000000000000000000000000000",
            y2: "0000000000000000000000000000000000000000000000000000000000000000",
            z2: "0000000000000000000000000000000000000000000000000000000000000000",
            x3: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y3: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z3: "0000000000000000000000000000000000000000000000000000000000000001",
        },
        {
            x1: "0000000000000000000000000000000000000000000000000000000000000000",
            y1: "0000000000000000000000000000000000000000000000000000000000000000",
            z1: "0000000000000000000000000000000000000000000000000000000000000000",
            x2: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y2: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z2: "0000000000000000000000000000000000000000000000000000000000000001",
            x3: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y3: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z3: "0000000000000000000000000000000000000000000000000000000000000001",
        },
        {
            x1: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y1: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z1: "0000000000000000000000000000000000000000000000000000000000000001",
            x2: "962d5804fc06af1072674188fb469da2645629fe77aa22489e7a32f6acd33154",
            y2: "dfb64a22a14b69a6a44eb3ddcee4ea39ef314f36108160e68d2f94d1f410c5b0",
            z2: "cb4d220591326ff0cdeb525c7045652f92892546864f03d54a3aea4795013192",
            x3: "5bba84f219242b9703f9a0ce844b7d044127f4a5f9b47ddcde908b41f8f1b9b1",
            y3: "441dbfb656edea56737adeddf7494cef4e8d97f8a1f3ec08fc51ef35477f5a36",
            z3: "40a10d30059e34113b7a4c342cb0437dd799f92b951752c18d96bafe4682e3c5",
        },
        {
            x1: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            y1: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            z1: "0000000000000000000000000000000000000000000000000000000000000001",
            x2: "1fd9fde65b84623a2657369da0b939a66f3f5d9f627bd9c75d8fe391f097aaf9",
            y2: "b74df0c213719d72fe7feb0321cbeb09af2bf3665a87a06743f80fcb21037704",
            z2: "2e82d28ea49da0bae39c561e6cb8073ad7e7f0e98d4ef516157a1f87ea03d0e6",
            x3: "3a0faa7c0e7bd04456364ebbc4b50d9210a6759e6a2801d3aa6664f9020256f9",
            y3: "5ed0d624ba6ca99e24a415fede25edfe8224ee3e1bf0ff399551f25c40e37da3",
            z3: "2cf78bb9101a0733bb88a3eb3a57512d8a9e2a0d092029e829d8edc3d25ffdef",
        },
        {
            x1: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            y1: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            z1: "0000000000000000000000000000000000000000000000000000000000000001",
            x2: "3b5fc66637f4d6bce70db2eba1175f7401df788fc58d7099881983262dd0f62e",
            y2: "f76e500a3ccd0cbd5e27bd746ceee92898d6f6fd5804c370ea2f14c0bbc47cbb",
            z2: "721ce4b29855911c8fa0edeb95a00400a994a2fcf14aea11179a804deff71e2f",
            x3: "ed0f990b91772d64e4af709677d3c1e665682173b5c019ead1ee5a1080d7c1f8",
            y3: "8a4df4bfef46f25258af3528384481ac355b819a5f7fbd12e31a94a88dffef37",
            z3: "c15d07f76e02b73695d4fecd8d91fe5aa9a93d58770d35da5e4dd8efadbe4ee7",
        },

        // in case of p1 == p2
        {
            x1: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y1: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z1: "0000000000000000000000000000000000000000000000000000000000000001",
            x2: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y2: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z2: "0000000000000000000000000000000000000000000000000000000000000001",
            x3: "5d22aa68d498ee29f8d1d7a0f7d73e2a5c46b961c0f1fe97ad8ede5f919a3db8",
            y3: "f1a409e68bc80e4ec9f667868feb70403f13c991b2a54f6372815b0780d78b4f",
            z3: "a72ea58024ebd536c38cf3200d248782b06e7aea94a97359a5d1cd8cb6cf0347",
        },
    }

    for _, tc := range tests {
        var p1, p2, p3 PointJacobian
        p1.x.Set(hex2element(tc.x1))
        p1.y.Set(hex2element(tc.y1))
        p1.z.Set(hex2element(tc.z1))

        p2.x.Set(hex2element(tc.x2))
        p2.y.Set(hex2element(tc.y2))
        p2.z.Set(hex2element(tc.z2))

        p3.x.Set(hex2element(tc.x3))
        p3.y.Set(hex2element(tc.y3))
        p3.z.Set(hex2element(tc.z3))

        var v PointJacobian
        v.Add(&p1, &p2)

        if p3.x.Equal(&v.x)&p3.y.Equal(&v.y)&p3.z.Equal(&v.z) != 1 {
            t.Errorf(
                "(%s, %s, %s) + (%s, %s, %s) should be (%s, %s, %s), got (%x, %x, %x)",
                tc.x1, tc.y1, tc.z1,
                tc.x2, tc.y2, tc.z2,
                tc.x3, tc.y3, tc.z3,
                v.x.Bytes(), v.y.Bytes(), v.z.Bytes(),
            )
        }
    }
}

func BenchmarkAdd(b *testing.B) {
    var p1, p2, p3 PointJacobian
    p1.x.Set(hex2element("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
    p1.y.Set(hex2element("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    p1.z.Set(hex2element("0000000000000000000000000000000000000000000000000000000000000001"))
    p2.x.Set(hex2element("3b5fc66637f4d6bce70db2eba1175f7401df788fc58d7099881983262dd0f62e"))
    p2.y.Set(hex2element("f76e500a3ccd0cbd5e27bd746ceee92898d6f6fd5804c370ea2f14c0bbc47cbb"))
    p2.z.Set(hex2element("721ce4b29855911c8fa0edeb95a00400a994a2fcf14aea11179a804deff71e2f"))

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        p3.Add(&p1, &p2)
    }
}

func BenchmarkAddDouble(b *testing.B) {
    var p1, p3 PointJacobian
    p1.x.Set(hex2element("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
    p1.y.Set(hex2element("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    p1.z.Set(hex2element("0000000000000000000000000000000000000000000000000000000000000001"))

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        p3.Add(&p1, &p1)
    }
}

func TestDouble(t *testing.T) {
    tests := []struct {
        x1, y1, z1 string
        x3, y3, z3 string
    }{
        {
            x1: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y1: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z1: "0000000000000000000000000000000000000000000000000000000000000000",
            x3: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y3: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z3: "0000000000000000000000000000000000000000000000000000000000000000",
        },
        {
            x1: "79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14",
            y1: "d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb",
            z1: "0000000000000000000000000000000000000000000000000000000000000001",
            x3: "5d22aa68d498ee29f8d1d7a0f7d73e2a5c46b961c0f1fe97ad8ede5f919a3db8",
            y3: "f1a409e68bc80e4ec9f667868feb70403f13c991b2a54f6372815b0780d78b4f",
            z3: "a72ea58024ebd536c38cf3200d248782b06e7aea94a97359a5d1cd8cb6cf0347",
        },
    }

    for _, tc := range tests {
        var p1, p3 PointJacobian
        p1.x.Set(hex2element(tc.x1))
        p1.y.Set(hex2element(tc.y1))
        p1.z.Set(hex2element(tc.z1))

        p3.x.Set(hex2element(tc.x3))
        p3.y.Set(hex2element(tc.y3))
        p3.z.Set(hex2element(tc.z3))

        var v PointJacobian
        v.Double(&p1)

        if p3.x.Equal(&v.x)&p3.y.Equal(&v.y)&p3.z.Equal(&v.z) != 1 {
            t.Errorf(
                "(%s, %s, %s) + (%s, %s, %s) should be (%s, %s, %s), got (%x, %x, %x)",
                tc.x1, tc.y1, tc.z1,
                tc.x1, tc.y1, tc.z1,
                tc.x3, tc.y3, tc.z3,
                v.x.Bytes(), v.y.Bytes(), v.z.Bytes(),
            )
        }
    }
}

func BenchmarkDouble(b *testing.B) {
    var p1, p3 PointJacobian
    p1.x.Set(hex2element("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
    p1.y.Set(hex2element("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    p1.z.Set(hex2element("0000000000000000000000000000000000000000000000000000000000000001"))

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        p3.Double(&p1)
    }
}
