package fugue

import (
    "bytes"
    "testing"
    "crypto/hmac"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

type testData struct {
    msg []byte
    md []byte
}

func Test_Hash224_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("e2cd30d51a913c4ed2388a141f90caa4914de43010849e7b8a7a9ccd"),
        },
        {
           fromHex("cc"),
           fromHex("34602ea95b2b9936b9a04ba14b5dc463988df90b1a46f90dd716b60f"),
        },
        {
           fromHex("1f877c"),
           fromHex("c4e858280a095030c40cdbe1fd0044632ed28f1b85fbde9b48bc3efd"),
        },
        {
           fromHex("c6f50bb74e29"), // 12 | 6
           fromHex("74b3eaf5370935cc997df0ff6b196906f582a951b546a3d38710e3c5"),
        },
        {
           fromHex("eed7422227613b6f53c9"), // 20 | 10
           fromHex("d1644b980cf16d6521bc708ac8968e746786ad310e6a62b17f43cb8d"),
        },
        {
           fromHex("3c5871cd619c69a63b540eb5a625"), // 28 | 14
           fromHex("e00371eb6928b1ec78a09fd9baa2dc17191ee8d264ccf22e507692f4"),
        },
    }

    h := New224()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New224 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        h.Reset()
        h.Write(test.msg[:len(test.msg)/2])
        h.Write(test.msg[len(test.msg)/2:])
        sum = h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New224 half fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum224(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum224 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash256_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("d6ec528980c130aad1d1acd28b9dd8dbdeae0d79eded1fca72c2af9f37c2246f"),
        },
        {
           fromHex("cc"),
           fromHex("b894eb2df58162f6c48d495f156e73bd086dd13db407ee38781177bb23d129bb"),
        },
        {
           fromHex("41fb"),
           fromHex("584827dea879a043438c23a32c42ba0990f0f8ce385852693b7eeb2bc4d7fab1"),
        },
        {
           fromHex("1f877c"),
           fromHex("f9f5cf602b093c43bf9c6d551f6a9e60214ce1bb3a6d842c3d9a5f358df05547"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("9041d9edf413cf0a8cfb6aed97c13032315319438be004685f4bb583f67acf23"),
        },
        {
           fromHex("21f134ac57"),
           fromHex("2fca43424b89301d8e1ba3c5eb760a8633639b35c5d72331c0a26ed4aee7e4ba"),
        },
        {
           fromHex("c6f50bb74e29"), // 12 | 6
           fromHex("70d683f0b39d3016fc243355a2e40a7f1337aa826fc88785a3f15c0d5e96eb1c"),
        },
        {
           fromHex("119713cc83eeef"),
           fromHex("5fb6e8b104bd05ff4b4606a5dbc204b1996ceac8721a0f988596ceb6ca38e431"),
        },
        {
           fromHex("4a4f202484512526"),
           fromHex("84e8df742af4ab3f552a148485a1d27943b57ba748b76a1cdf8e1f054bed3d7b"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("0f0e687507e64d63234cc50e627dd1a0a51c6c06ad45fb32604c5921e37daa2a"),
        },
        {
           fromHex("eed7422227613b6f53c9"), // 20 | 10
           fromHex("3cfb02bd515e9d983cc1665ad9368f77c89fee97eb574bf7db8c3d8e44396fb9"),
        },
        {
           fromHex("eaeed5cdffd89dece455f1"),
           fromHex("2cf0a9ba776998481c86cc66ae958942cc2e0ccc72b4094d8628731c0a9366b8"),
        },
        {
           fromHex("5be43c90f22902e4fe8ed2d3"),
           fromHex("d94c33e8312522b6393ebdfb4c99137265c8965782e4d7b4495640bfd6a75760"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("6fcedcfd9d830702c0e4efcbb19a305449f402a6e7f02bf4236c8bae69f28b31"),
        },
        {
           fromHex("3c5871cd619c69a63b540eb5a625"),
           fromHex("140bb7182339669ea91422ef67f332c7048d5e4a14875b3fda16d2ec5432dc46"),
        },
        {
           fromHex("fa22874bcc068879e8ef11a69f0722"),
           fromHex("af6e59a0291236d31c8ed4e05dd121125dcd9b70411dfa9d2e2be7423ed2d358"),
        },
        {
           fromHex("3c5871cd619c69a63b540eb5a625"), // 28 | 14
           fromHex("140bb7182339669ea91422ef67f332c7048d5e4a14875b3fda16d2ec5432dc46"),
        },
    }

    h := New256()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New256 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        h.Reset()
        h.Write(test.msg[:len(test.msg)/2])
        h.Write(test.msg[len(test.msg)/2:])
        sum = h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New256 half fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum256(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum256 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash384_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("466d05f6812b58b8628e53816b2a99d173b804a964de971829159c3791ac8b524eebbf5fc73ba40ea8eea446d5424a30"),
        },
        {
           fromHex("cc"),
           fromHex("436868cd6804b803dac432ed561bb40f91f624a10f2a368702359841cfda6909115628ca4977b3f8063a3b87fc7a0984"),
        },
        {
           fromHex("1f877c"),
           fromHex("47fc7c9df32d8ffad51d840de2da1908dd0993340e965b425f8bbba468239973e349394bcfe288b4ee467772bfd26939"),
        },
        {
           fromHex("c6f50bb74e29"), // 12 | 6
           fromHex("ad340157dd68e0c8af60d8e926b0e3a721d93627da58fa77c4df14df56c324e4f711e64c0ad6346a949ecf0185ab6e1f"),
        },
        {
           fromHex("eed7422227613b6f53c9"), // 20 | 10
           fromHex("8ced5b9b5f0c5771d869b8423117b39511fefeaee1dea47368473ec65ee0c0e02b9f41a3b64c6fa65f4ba520bfd36ff0"),
        },
        {
           fromHex("3c5871cd619c69a63b540eb5a625"), // 28 | 14
           fromHex("76ece1c5dda393c24c98804cb5e93f69e6075d9fa8f7cbe3f695c6ef16a26757dd628efb83ffc92aad4dd774396016a0"),
        },
    }

    h := New384()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New384 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        h.Reset()
        h.Write(test.msg[:len(test.msg)/2])
        h.Write(test.msg[len(test.msg)/2:])
        sum = h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New384 half fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum384(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum384 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash512_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("3124f0cbb5a1c2fb3ce747ada63ed2ab3bcd74795cef2b0e805d5319fcc360b4617b6a7eb631d66f6d106ed0724b56fa8c1110f9b8df1c6898e7ca3c2dfccf79"),
        },
        {
           fromHex("cc"),
           fromHex("2ef4115479b060fc64a4d6f6913a39e326afc81deb4e39d71c573df5ed132200e7c784bab1804930cad16847f16cbda59a865bbd928ebc17d33689fef233c10b"),
        },
        {
           fromHex("1f877c"),
           fromHex("deea1a90bf692f13974943e0ceeb551cf94903bde784278fb52a2b61750d093ab4eb662edb36ffc3c184ce753621173928e5fa58f7df7449d8888a56f238d936"),
        },
        {
           fromHex("c6f50bb74e29"), // 12 | 6
           fromHex("172dd6328695a30e9dbd7d6f805b43836f1003c242be47d95d83a4f0a7bbc6d7b0e84697002fb7707fdeaa305c60adb56a6a9b25b227a3fe16cd6602742f5125"),
        },
        {
           fromHex("eed7422227613b6f53c9"), // 20 | 10
           fromHex("c98a7a5c4795a41d2c8334f97f58e6f00d6c69a46b22ef36e09412347d5756b142439d7402f1f528a9060c022723a644f12c7a2cc53512edfb0692d24774cf21"),
        },
        {
           fromHex("3c5871cd619c69a63b540eb5a625"), // 28 | 14
           fromHex("5707b902292411e8bc8b63f675d568507f98ca3c0dcca18ad72908bc2e2aa9bb9f3a9349867a6badf71bb55f2612e9f59ad25d7f00b270ed581e065089b90812"),
        },
    }

    h := New512()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New512 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        h.Reset()
        h.Write(test.msg[:len(test.msg)/2])
        h.Write(test.msg[len(test.msg)/2:])
        sum = h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New512 half fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum512(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum512 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash256_Hmac_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("327ab04111c87bcdd3692072bc2dd58809ac97894483ef25eaa51577e1808dec"),
        },
        {
           fromHex("cc"),
           fromHex("469be4dc3d5068ad624d2e32214ad26d19d56d932d6d53cc2969690f5683ae6e"),
        },
        {
           fromHex("41fb"),
           fromHex("ce242fadf9e290db1282df69f8064515cc8a094c23d8285440fed5a70aadf288"),
        },
        {
           fromHex("1f877c"),
           fromHex("36a6963f05d41e0b712d34317ae3e5e92ccf7d7ebcbbdf4fd614de42239f9756"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("3f1b101c70613cb3951209cdb8d4a2e18abf0fc5018b83961626e881acc2b69d"),
        },
        {
           fromHex("21f134ac57"),
           fromHex("2fe874afa43eb11b62aac63ea1751038020f67750b306c9de2d7bc21f99abb28"),
        },
        {
           fromHex("c6f50bb74e29"), // 12 | 6
           fromHex("34819f943d467b7a260e886b95388c7b9146180e5717e338b55b1ddfaf11adab"),
        },
        {
           fromHex("119713cc83eeef"),
           fromHex("79934086689a21269792f7fab2ed944b424593cdab6004cf9176149634c18b51"),
        },
        {
           fromHex("4a4f202484512526"),
           fromHex("beddc19a567bad0e48c41dddad4c53509192334e2d270f5ed0a102ea1fcd5adf"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("5b601a2552280235624b35e9fe9c31af6318202229c381f94d20ac8737071a8f"),
        },
        {
           fromHex("eed7422227613b6f53c9"), // 20 | 10
           fromHex("dc1b418f2a814f0cdf5bf17303466e136abb29117553f5d0b4021157609bf007"),
        },
        {
           fromHex("eaeed5cdffd89dece455f1"),
           fromHex("f350e4f512b1c615a756c58e37bf3dc879ae818a34912a54e5a6a6d7e628c358"),
        },
        {
           fromHex("5be43c90f22902e4fe8ed2d3"),
           fromHex("8d37aa57c3eadd3d7c4dd0defd265d439848b2d28439caf1623ec2935b850319"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("9718163e75e751aec18225184696791740a96e8764438a52613e765089fe80d4"),
        },
        {
           fromHex("3c5871cd619c69a63b540eb5a625"),
           fromHex("ffdc05af40667d0db0d0666181532975c937a7dfbaa9d67a5906924d0fc67039"),
        },
        {
           fromHex("fa22874bcc068879e8ef11a69f0722"),
           fromHex("8ba8ec52bf7cc2f3c43fe642382004cff43e477980e92a845655ed90da8eefef"),
        },
    }

    key := []byte("1234567812345678")

    h := hmac.New(New256, key)

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] Hmac With New256 fail, got %x, want %x", i, sum, test.md)
        }
    }
}
