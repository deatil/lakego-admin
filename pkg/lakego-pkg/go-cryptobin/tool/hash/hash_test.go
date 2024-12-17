package hash

import (
    "fmt"
    "testing"
)

func Test_Hash(t *testing.T) {
    cases := []struct {
        name   string
        src    string
        hashed string
    }{
        {
            "MD2",
            "Discard medicine more than two years old.",
            "3ca2b9f3f346747a8bd3e58dfc200822",
        },
        {
            "MD4",
            "Discard medicine more than two years old.",
            "1b5701e265778898ef7de5623bbe7cc0",
        },
        {
            "MD5",
            "He who has a shady past knows that nice guys finish last.",
            "bff2dcb37ef3a44ba43ab144768ca837",
        },
        {
            "SHA1",
            "Discard medicine more than two years old.",
            "ebf81ddcbe5bf13aaabdc4d65354fdf2044f38a7",
        },
        {
            "SHA224",
            "Discard medicine more than two years old.",
            "19297f1cef7ddc8a7e947f5c5a341e10f7245045e425db67043988d7",
        },
        {
            "SHA256",
            "Discard medicine more than two years old.",
            "a144061c271f152da4d151034508fed1c138b8c976339de229c3bb6d4bbb4fce",
        },
        {
            "SHA384",
            "Discard medicine more than two years old.",
            "86f58ec2d74d1b7f8eb0c2ff0967316699639e8d4eb129de54bdf34c96cdbabe200d052149f2dd787f43571ba74670d4",
        },
        {
            "SHA512",
            "Discard medicine more than two years old.",
            "2210d99af9c8bdecda1b4beff822136753d8342505ddce37f1314e2cdbb488c6016bdaa9bd2ffa513dd5de2e4b50f031393d8ab61f773b0e0130d7381e0f8a1d",
        },
        {
            "RIPEMD160",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
        },
        {
            "SHA3_224",
            "Discard medicine more than two years old.",
            "42e169df4ebe0e5f3a9fcf97dfbda432a2caede22dd662473d09378d",
        },
        {
            "SHA3_256",
            "Discard medicine more than two years old.",
            "e3b22a5c33f8001b503c54c3c301c86fd18fee24785424e211621a4e7184d883",
        },
        {
            "SHA3_384",
            "Discard medicine more than two years old.",
            "f61de1a171ab20c26eacd4ef67c3c456bac8e6f88ee45d25a2b8847e50223327659b88c956847582d9ebf1d68f67c351",
        },
        {
            "SHA3_512",
            "Discard medicine more than two years old.",
            "cdbe0f69c23a9e28868ba75199c7f1a8b3981e2e2acb4ec0e4c0b2909748aa5ad694df8421fa7227b126c8630bd8d7df10abf9af8175d3b14f48d067f0d45751",
        },
        {
            "BLAKE2s_256",
            "Discard medicine more than two years old.",
            "ada506c9ba530e0869265fbfb89a97c9974f3c1f2fdb695d140cb1e459e53ec0",
        },
        {
            "BLAKE2b_256",
            "Discard medicine more than two years old.",
            "c68ba663bc8ffca07c0f0df23fda31c9576ef7d1311c7fe9ea7571e1a1e9c27f",
        },
        {
            "BLAKE2b_384",
            "Discard medicine more than two years old.",
            "206ba7f4fb7b3a630ccda726c76a11efb07e9a00b43527c4b9ffe38785df9361ffc156688e2a8ab63b3e12155f7dcd03",
        },
        {
            "BLAKE2b_512",
            "Discard medicine more than two years old.",
            "daac648da85a0667999f43d1aa7b64291b21dff7191cce7eeb8a18c93d0317b2817df83bb1ccbe2342ea18c9f622f2adc1329282fa6291e2bb62e5d191e73b0c",
        },
        {
            "SM3",
            "Discard medicine more than two years old.",
            "8a89bd24087ae6f9a3aae485bfa9ecd276f909a04b248eab1b4f9be2b24f0111",
        },
        {
            "GOST34112012256",
            "Discard medicine more than two years old.",
            "86b0fa34d4c7ca23faea1decd157f10c8c0a91824f4ce6ce60679752b66902c9",
        },
        {
            "GOST34112012512",
            "Discard medicine more than two years old.",
            "a9b8eef57cc0b453508e09e69b458d9d352574952f9f3649c1f4384e0f3d3f2021e52338e19a0ac12c583354332879f65489bf649422447866cdec5394c54b4b",
        },
    }

    for _, c := range cases {
        {
            h, err := GetHash(c.name)
            if err != nil {
                t.Errorf("%s: failed to create hash: %v", c.name, err)
            }

            newHash := h()
            newHash.Write([]byte(c.src))

            hashed := fmt.Sprintf("%x", newHash.Sum(nil))

            if hashed != c.hashed {
                t.Errorf("%s: want %s, got %s", c.name, c.hashed, hashed)
            }
        }

        {
            hashed0, err := HashSum(c.name, []byte(c.src))
            if err != nil {
                t.Errorf("%s 2: failed to create hash: %v", c.name, err)
            }

            hashed := fmt.Sprintf("%x", hashed0)

            if hashed != c.hashed {
                t.Errorf("%s 2: want %s, got %s", c.name, c.hashed, hashed)
            }
        }
    }
}
