package curve256k1

import "testing"

func TestTable(t *testing.T) {
    myTable := []struct {
        x, y, z string
    }{
        0: {
            x: "0000000000000000000000000000000000000000000000000000000000000000",
            y: "0000000000000000000000000000000000000000000000000000000000000000",
            z: "0000000000000000000000000000000000000000000000000000000000000000",
        },
        1: {
            x: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            y: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            z: "0000000000000000000000000000000000000000000000000000000000000001",
        },
        2: {
            x: "7d152c041ea8e1dc2191843d1fa9db55b68f88fef695e2c791d40444b365afc2",
            y: "56915849f52cc8f76f5fd7e4bf60db4a43bf633e1b1383f85fe89164bfadcbdb",
            z: "9075b4ee4d4788cabb49f7f81c221151fa2f68914d0aa833388fa11ff621a970",
        },
        3: {
            x: "32a43be6c1b5fad475943a45178c20f2f637e1d645a21880dbe5e8d63c226120",
            y: "e5280c4ff42395517d803ab3914fa6a2c0a483c04a6bf3e9addb61444d116b55",
            z: "db7a0ac7e8c1b8b8802b2be29248606876f5802cbb422d6fdf447329aac9410a",
        },
        4: {
            x: "9bae2d5bac61e6ea5de635bca754b2564b7d78c45277cad67e45c4cbbea6e706",
            y: "34fb8147eed1c0fbe29ead4d6c472eb4ef7b2191fde09e494b2a9845fe3f605e",
            z: "c327b5d2636b32f27b051e4742b1bbd5324432c1000bfedca4368a29f6654152",
        },
        5: {
            x: "88c156dc6ce08bfdebdad85cdf206ff46f829bf7f30e6f1853bee30096070348",
            y: "fdae97c967d36e33e591789354079dffa31c92205f97ac4e7d67d0da2f34acb3",
            z: "70ce1c5e15667cb8c28b16b0e773f9148cc0c2ff2b01ff06ca20e61cf7a2f40e",
        },
        6: {
            x: "9bd74c7352f57032c5ee6d51cb1e8980ec2e92027d7e6e252931dbca82478738",
            y: "ae72c0d3c849bccd07463f61e7fbe5b636389add7cc6ed8cbce4f34c0da3016f",
            z: "bba49beb75cce4340bad30e143dcdce0ba1469cd0bdd88abc5c645f5b1c2a714",
        },
        7: {
            x: "4e17c6d4299f6f12d826c968f75f959c9e77b4059d7c5ebeb8fd504be041a294",
            y: "8bfbb017b80fc2a1a6d4ce6e0090a365c09020d46bc760d537cedf010f732ba4",
            z: "c931cdfc342d6ea21624b934a4eaa99b57095396d2dce539a65eac2b3e36f075",
        },
        8: {
            x: "1fd9fde65b84623a2657369da0b939a66f3f5d9f627bd9c75d8fe391f097aaf9",
            y: "b74df0c213719d72fe7feb0321cbeb09af2bf3665a87a06743f80fcb21037704",
            z: "2e82d28ea49da0bae39c561e6cb8073ad7e7f0e98d4ef516157a1f87ea03d0e6",
        },
        9: {
            x: "3a0faa7c0e7bd04456364ebbc4b50d9210a6759e6a2801d3aa6664f9020256f9",
            y: "a12f29db45935661db5bea0121da12017ddb11c1e40f00c66aae0da2bf1c7e8c",
            z: "d3087446efe5f8cc44775c14c5a8aed27561d5f2f6dfd617d627123b2d9ffe40",
        },
        10: {
            x: "f1e55600a35fdd80f7001b1e52844b2efa9073eac4bd2b8d077b70b842996c7a",
            y: "5054e01516ee4d95d97f105b312d4d211a18ad9e4ce9c0953b46c87b009cac66",
            z: "83d249b669b5895e4da36dacbf19b92494a70db9bb05958da1f46c6b8c456f94",
        },
        11: {
            x: "8198a6e2e0197c2ceac043861a60a35b949e9ab8f43e9845253651f5b2a5a2e5",
            y: "13950da1bd3f23fda650f9e23eeebe5575adcc44e12401b922450461498d20b9",
            z: "f0c670829c6179417d12a54e8e285c3a13656c3c798a6a5e73024c9aedc913dd",
        },
        12: {
            x: "4c002a334a7d6758efdf9446ea4b8d38cf51e106eb2518215ab34c3c8b1f748d",
            y: "bac9dc42b0a98a3f284094dc077996e2c02d35f0b454bb2520c165edb0f808f8",
            z: "c8da4dee315d814671bb3c330f23e2c059bb730cf5985f2e5114bba63b176d47",
        },
        13: {
            x: "b3d3a82530a70e2dcaaeb24bf250b594b9af3f11ea16af58f888ae1044f47f62",
            y: "1bc0ab2f044fae9dbecb292fae319d8a219e8a74ef4ed68c10970bf70b4bc243",
            z: "fff937d0439c628338ffac28167db11545f19da86f2bc26d3535edbf1a634e0e",
        },
        14: {
            x: "cd6c152a9cf068ce858db95d7f805d0423f35a4c4e5205bb534d5d7cbd4d7ce4",
            y: "b1f8a84fa7802b449cbf410ffe18cbce1dab81e0c9522304138827eba2805c13",
            z: "bf47d8e66d26c4691050e902d8866cc233e8ce667c1bf26d494584320d82e465",
        },
        15: {
            x: "b1ad9e1bc3f46865c6ffb1a9defdc90ce0a8e6d0854e8b2dd19e09246e920060",
            y: "06f3deacd45e52727d61ea870c714e2f4f99fe1dd1b473a90c9dc43ac5d62145",
            z: "e6c2db1c3591b3da280426d9510374fcf5e098b071e1d1810a86178e2337de5b",
        },
    }
    var q PointJacobian
    q.x.Set(hex2element("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"))
    q.y.Set(hex2element("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"))
    q.z.Set(hex2element("0000000000000000000000000000000000000000000000000000000000000001"))

    var table lookupTable
    table.Init(&q)

    for i := 0; i < 16; i++ {
        var want, got PointJacobian
        table.SelectInto(&got, uint8(i))
        want.x.SetBytes(decodeHex(myTable[i].x))
        want.y.SetBytes(decodeHex(myTable[i].y))
        want.z.SetBytes(decodeHex(myTable[i].z))
        if want.Equal(&got) == 0 {
            t.Errorf("table[%d].x: want %x, got %x", i, want.x.Bytes(), got.x.Bytes())
            t.Errorf("table[%d].y: want %x, got %x", i, want.y.Bytes(), got.y.Bytes())
            t.Errorf("table[%d].z: want %x, got %x", i, want.z.Bytes(), got.z.Bytes())
        }
    }
}
