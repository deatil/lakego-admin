package drbg

import (
    "hash"
    "bytes"
    "testing"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/hash/sm3"
)

var testsHmac = []struct {
    newHash               func() hash.Hash
    entropyInput          string
    nonce                 string
    personalizationString string
    v0                    string
    entropyInputReseed    string
    additionalInputReseed string
    v1                    string
    additionalInput1      string
    v2                    string
    additionalInput2      string
    returnbits1           string
    v3                    string
}{
    {
        newHash: sha1.New,
        entropyInput: "7d7052a776fd2fb3d7191f733304ee8b",
        nonce: "be4a0ceedca80207",
        personalizationString: "",
        v0: "8bd11c639be35d012b8fa9358b25b8996b100b0d00000000",
        entropyInputReseed: "49047e879d610955eed916e4060e00c9",
        additionalInputReseed: "fd8bb33aab2f6cdfbc541811861d518d",
        v1: "5c754b7134f409d22552a30aa674b1b3a0a590a700000000",
        additionalInput1: "99afe347540461ddf6abeb491e0715b4",
        v2: "c4ecfaadba781a1c10b7756470bbbc1eff813a0800000000",
        additionalInput2: "02f773482dd7ae66f76e381598a64ef0",
        returnbits1: "a736343844fc92511391db0addd9064dbee24c8976aa259a9e3b6368aa6de4c9bf3a0effcda9cb0e9dc33652ab58ecb7650ed80467f76a849fb1cfc1ed0a09f7155086064db324b1e124f3fc9e614fcb",
        v3: "15d2c57b07db598f83f07d67b23c6772c3ccf4b200000000",
    },
    {
        newHash: sha1.New,
        entropyInput: "11c0a7e1472cec70fa8c1ca15759ac5b",
        nonce: "b1c73c22db39cd7b",
        personalizationString: "b24e392cb1f3c18af2cb50feac733e32",
        v0: "19a03422ae972aa8b3c6f9f06cd8d67cf32c1bde00000000",
        entropyInputReseed: "c6ab59ff708a5c1f598e75df060e1981",
        additionalInputReseed: "",
        v1: "dc831116739734241418a975dcac594eb13c637000000000",
        additionalInput1: "",
        v2: "db1b24a92bbb6d7638ce376f9ec0df515291a19600000000",
        additionalInput2: "",
        returnbits1: "070e603cd48d56430a5ab461a751ec2a4a6aa6fb6ee52efe9a41e4611eafdfc957184b47bbb017e484ac34c7de56cd7813feb301b5befce573ad0a254e6cfe35b77c30be6b7cb5e7efa72813c7546ba5",
        v3: "d3ab4ccd28b9104be57eac8b6fa293497a1ba27300000000",
    },
    {
        newHash: sha256.New224,
        entropyInput: "29a7071e686936e60c392061f71b68500dd6f11c563732fc",
        nonce: "a9dec3b2f859e06a857fd94e",
        personalizationString: "",
        v0: "d811a84f9d8daa30dfdaaf9c8b4c3f2c6569949e97064c79",
        entropyInputReseed: "3ca1817872d94c2b7c2f283a0d2d12a6443e95f7e700a910",
        additionalInputReseed: "",
        v1: "d74d59ad846eee1c44c0b68e401ab7efb1bee9432e8957ad",
        additionalInput1: "",
        v2: "72f4961e421e61a42cabd4ab0db394d8de40a43af00916d3",
        additionalInput2: "",
        returnbits1: "72c0f3cb7792bfebbc1ee6f65d40d118a6a1c4e04e589c8f70273b4c7b718c9df383658572b894838a311fc0aa2aa6258758b33783e192b0c3c1d322809375dc925a05605fed8c7e8fb878fb63c84ce639fd277d9955f91602a9f4777b7c3b15404c4e761ec8d466674e32136c7b8bdb",
        v3: "978448c123fad08c9031c66594f5c5f3b48de85b612e6c1a",
    },
    {
        newHash: sha256.New224,
        entropyInput: "fdca0039e8485a06e6a9afbde5b07a1bbe49e13659a21640",
        nonce: "34289639d23dcf3f9874b8fb",
        personalizationString: "",
        v0: "ffd84e91bede76fc1d4155d9b31eec97c044e775c2be483b",
        entropyInputReseed: "1a1af8495b6b2129b88475cc529c96271bc1bbb5c7c2ea03",
        additionalInputReseed: "841f765ed5f00be838a270730ce5926659cd7cd9d5b93ca5",
        v1: "e7ffa890b11e440b1d8fd3666ace1aa8a1eb237ee87fc7bb",
        additionalInput1: "825fa13ed554973768aab55917cc880183c3ebb33a532305",
        v2: "eeb32d6d305b1546d5c823c0ade0f14ee5092c13661c73a0",
        additionalInput2: "736e9de931198dd1c5f18a7da3887f685fbfa22b1d6ab638",
        returnbits1: "dd8596a62847a77da81818dbbeaf0393bd5e135069ba169f8987f01dc756689342cba61d87a79d4bce2311790069d10709c3a53df974c7d6793ae1298253f13ecdbb5680928579b73d73afdcd24a703dc9b391f303d8835ba1129c3d46237ede5e44732a74f8f23b60a3a45ce42f042a",
        v3: "cf127ca97e13fb16b5d058c9c05337609643fced549819b1",
    },
    {
        newHash: sha256.New,
        entropyInput: "cdb0d9117cc6dbc9ef9dcb06a97579841d72dc18b2d46a1cb61e314012bdf416",
        nonce: "d0c0d01d156016d0eb6b7e9c7c3c8da8",
        personalizationString: "6f0fb9eab3f9ea7ab0a719bfa879bf0aaed683307fda0c6d73ce018b6e34faaa",
        v0: "6c02577c505aed360be7b1cecb61068d8765be1391bacb10",
        entropyInputReseed: "8ec6f7d5a8e2e88f43986f70b86e050d07c84b931bcf18e601c5a3eee3064c82",
        additionalInputReseed: "1ab4ca9014fa98a55938316de8ba5a68c629b0741bdd058c4d70c91cda5099b3",
        v1: "21a645aeca821899e7e733a10f64565deee5ced3cd5c0356",
        additionalInput1: "16e2d0721b58d839a122852abd3bf2c942a31c84d82fca74211871880d7162ff",
        v2: "490c0b7786c80f16ad5ee1cc0efd29618968dce14cccebec",
        additionalInput2: "53686f042a7b087d5d2eca0d2a96de131f275ed7151189f7ca52deaa78b79fb2",
        returnbits1: "dda04a2ca7b8147af1548f5d086591ca4fd951a345ce52b3cd49d47e84aa31a183e31fbc42a1ff1d95afec7143c8008c97bc2a9c091df0a763848391f68cb4a366ad89857ac725a53b303ddea767be8dc5f605b1b95f6d24c9f06be65a973a089320b3cc42569dcfd4b92b62a993785b0301b3fc452445656fce22664827b88f",
        v3: "47390036d5cb308cf9592fdfe95bf19b8ed1a3db88ed8c3b",
    },
    {
        newHash: sha512.New384,
        entropyInput: "f7e64a9bff8fba0efb028c0f01285a0c30b550e15814e4377b3ecf6050d7d37e",
        nonce: "45c98564cde8445f83df7ca3ae42dd4a",
        personalizationString: "6122bf4b1d722ee2f42cb32f18b36aa1c61b9d18036fd2c9c61e4ad8eb0f047a",
        v0: "5673f8891f1c74502772c361d0510835e8c38509160821d4",
        entropyInputReseed: "bfe7429dc2a4cdcd2816f170c81f7358cf957073d696401a761b9dc6af1bf457",
        additionalInputReseed: "6f2c3bf3833894857e06e5a336028b0b8e6f60962bb2ce18da5d6d86229f98f2",
        v1: "d36eaafdba0388019bbeb9abf008c43f348a408892385724",
        additionalInput1: "fe7e0bb856ca9d49553cf00ec1ef8a2ff2d213de19ca07cc37d192eb32fa319b",
        v2: "0d3200290880a1fa2a7fed6822e550f8f41ca8259a2223e1",
        additionalInput2: "66caf1f1b8b6f12f8ad65060551d87edcbaf25ac2efecc303e624988c514d84e",
        returnbits1: "d97d3ad44a650438a0cc32fac69d9cf27230838dc7142b147ecaa453fe02dbaf59aa048b004966b7852730a6a374a1cd430177a6c02f3027bfda2165325da790d3ca9c41f6d8a1fd168fa60333699a58059a484d6363fff18df3c9b2f5e9b9fe7491df371c73cc84d321f580bb6ce6179cb017228f67c401b53aadeb21365e3044815a8cb38a8e1523913fec668a021d42a2af4bcebff900a2eb15e3f39d06f91629adf4bc61b38eb10d5e6265aeba11565aa9c5e033f2b109c71bf6e49c0137",
        v3: "127f7d7f9b5a4380ef268b3d0c3c4dc827e2aeb496bdde29",
    },
    {
        newHash: sha512.New,
        entropyInput: "73cc8caea7f1f2129bd035b77bba2309ca3bec73e9f993fbcce7e3f148670bca",
        nonce: "656e3f17e5a8ce9bfe3665f4b6ca8ac8",
        personalizationString: "eef338ebdf4d9399441655090136becbcaf277e5ac73426f79552b3f27819ab6",
        v0: "c88daa984ab70e96a6aedac20f436ae0dc30f4fac7fde4ab",
        entropyInputReseed: "111fe051ee0e760b295b73470da27081ff17bfcd6ff9085c5e064ab844927f84",
        additionalInputReseed: "2114d320b65a5906d04c5166ee82e727cc53f0ba33ed54a3229ad9592995695d",
        v1: "fef3d9a68024fdfd6115878a38d89453ed91a842e0fdf8b5",
        additionalInput1: "e3fce46cd5c90936f20252e0065dee1940c7902198ae105017a8f50d143a50f6",
        v2: "60c8102686341d5108051476c4543c4cebbbdb56396264f1",
        additionalInput2: "7ad27ea94de6ec7ad7cc1895381c735f007f6087d688a070b4cdfaecdd2a3345",
        returnbits1: "858108fe1adf90fb3238363ce3532362675a462563e5c12df97d054267df0b205ed3960d86893c93d2b1997d95abd9179512289297b00cacd1a51202923c4224561e9986d0242f50ea4667fd6402e29d18c184028cc6c85836b1455e2d2e9b389e0d65bcd2c78d5e42ad9e47707c9dd4617e6ef2d64590d0e0be5e4465eb611d91b1a45bca1af04632fc8dd045a5f5ba3ec1fc09e3aaa1d03719181e11c80dcd1c4d1aac3ca69d89b9d2c6ff7575d78843fc4695c1954fc663732418bddba4b20439da03d0428fa047f99a378447f9e563fe405fd8f9c32d580aa6dc1560b9df1530fcc7b337072cb60007b4e2762dc61a08e6511e7c93b91303aa3d46c14483",
        v3: "e9dcdcd2f8f1a2393bcc63ad756e584eea6074a3e54b31a8",
    },
    {
        newHash: sha512.New512_224,
        entropyInput: "10dfb97e42ddc0335c5bc1e0bdc9946c9981a79c93c2e7bc",
        nonce: "6d77de8f8ed3f8d0922676a1",
        personalizationString: "ee154a5cc5d13c219a09c1612b8fdb0c806efabff147df3d",
        v0: "f6b810f422fc29f6b405445a8e4d2d01139513f6cd43fe66",
        entropyInputReseed: "917b6dd74dfddd35d1a39c76b709520a3a3868994950c806",
        additionalInputReseed: "46cd4ff692092a3972f6f94d0987f741c2e9ab876bcf1f09",
        v1: "50b7367ab9e36ba5ad0452f5aee2fce5df96dfe1c69ba631",
        additionalInput1: "11631e48c7c81649668fd45dbe612afd70be64cc9a511eba",
        v2: "cd764434628dca2e0f93509c254c64559e735de70593ecf3",
        additionalInput2: "af282b50be2121512d44e7540396a7b76093176070c3f843",
        returnbits1: "2d516dcddf579cb408408ff44a5cda00de601cc2f39fc59fabbcadf694236beb8f0c564239b6fa4a1f7c109c7f381077ca026c568e03575954ab9815d799a4a4728cb1ebcf593f79530e7b65a7008846e59180fb38c6270003af9385ca00c7c0ebf48745bd3c69b438effe382d620ae5",
        v3: "e42e3457a1a93ec7e2bda5c43ae019ef411093ee888b134e",
    },
    {
        newHash: sha512.New512_256,
        entropyInput: "5762fb19f1ea0d9c327a2a4d108e91ccd18f72b85dbd9df0954b7d2b3d02e312",
        nonce: "355f17ffee210053373332e535fb657c",
        personalizationString: "",
        v0: "069f7a550479fea75c7cc77520cf21deaa7d07245a49b977",
        entropyInputReseed: "37de2db71e66fafc5441556686aec874aaedc1085f7c2505560bd2b5ccbff943",
        additionalInputReseed: "ce47133c1f6b32d5c97e746fcde8dcf260553a2aedb7eb0ffe480a9e764a282f",
        v1: "b993818a8a6afdba578188c5fe7110fa4d5a0d7c7fd91fae",
        additionalInput1: "f8c3aa39ceaf85204b8036980adaa7be61ef04ac5b8430046bf1ffe9108a245e",
        v2: "71c201b125d205d2fdea6fcbf4e532c2007f7a1da8c7600f",
        additionalInput2: "ed812f762e1871e6467cd953f3dbb73fdf31bb76e657242cba82cc6b9a2e7c1d",
        returnbits1: "25127b184c707ea16c4ba5231c9a312fb18faf8b2afe38672534018f7f8086e43cd60ebea35280238ab4295865d32f98f86223918d848ff6108ee608eae96a24f2db52a14fdd3229e32594b2f510792677ae18328a3e6b492e1c25b7ada87741f2624966a33647d7351419eee2d601d7dc47e8e16e2a803bcb9715ddbe991b70",
        v3: "78240cef47bbbf353033815e15d6afdbe76a7451be3381f8",
    },
    {
        newHash: sm3.New,
        entropyInput: "5252fb19f1ea0d9c327a2a4d108e91ccd18f72b85dbd9df0954b7d2b3d02e312",
        nonce: "355257ffee210053373332e535fb657c",
        personalizationString: "",
        v0: "68d960e46d6d62639ff6b3d65ba377a1a6a63be2479ac414",
        entropyInputReseed: "37de2db73566fafc5441556686aec874aaedc1085f7c2505560bd2b5ccbff943",
        additionalInputReseed: "c357133c1f6b32d5c97e746fcde8dcf260553a2aedb7eb0ffe480a9e764a282f",
        v1: "36a50cf789cc5509717a967e64228a0a052f54be60a8b669",
        additionalInput1: "f8c3a359ceaf85204b8036980adaa7be61ef04ac5b8430046bf1ffe9108a245e",
        v2: "9b0047227b089176086ff7b18478a6c9510e29361d000c60",
        additionalInput2: "ed352f762e1871e6467cd953f3dbb73fdf31bb76e657242cba82cc6b9a2e7c1d",
        returnbits1: "b040b72948af0f73b48e3bf91cb6a13b36808b3dc5931416e018486247c9ded53c0d3c776fc9dd18ab215f4e27c45e3f6affcf8a7af387e2526bab9881d5123d7ed3f968531d317e73f162283f1a116afcde553a089e9b6b2ea4bdf331cf8d8afd0bd741cb21d4f1477084ac7dab4df0bbf08cf8aa20e11cdd861d4b010c755a",
        v3: "2a62a2ee36fb719b4a453ad1c07307196f4ec9d645283408",
    },
}

func Test_HMAC(t *testing.T) {
    for _, test := range testsHmac {
        entropyInput, _ := hex.DecodeString(test.entropyInput)
        nonce, _ := hex.DecodeString(test.nonce)
        personalizationString, _ := hex.DecodeString(test.personalizationString)
        v0, _ := hex.DecodeString(test.v0)
        hd, err := NewHMAC(test.newHash, entropyInput, nonce, personalizationString)
        if err != nil {
            t.Fatal(err)
        }

        if !bytes.Equal(hd.v[:len(v0)], v0) {
            t.Errorf("not same v0 %x, want %x", hd.v[:len(v0)], v0)
        }

        // Reseed
        entropyInputReseed, _ := hex.DecodeString(test.entropyInputReseed)
        additionalInputReseed, _ := hex.DecodeString(test.additionalInputReseed)
        v1, _ := hex.DecodeString(test.v1)
        hd.Reseed(entropyInputReseed, additionalInputReseed)

        if !bytes.Equal(hd.v[:len(v0)], v1) {
            t.Errorf("not same v1 %x, want %x", hd.v[:len(v0)], v1)
        }

        // Generate 1
        returnbits1, _ := hex.DecodeString(test.returnbits1)
        v2, _ := hex.DecodeString(test.v2)
        output := make([]byte, len(returnbits1))
        additionalInput1, _ := hex.DecodeString(test.additionalInput1)
        hd.Generate(output, additionalInput1)
        if !bytes.Equal(hd.v[:len(v0)], v2) {
            t.Errorf("not same v2 %x, want %x", hd.v[:len(v0)], v2)
        }

        // Generate 2
        v3, _ := hex.DecodeString(test.v3)
        additionalInput2, _ := hex.DecodeString(test.additionalInput2)
        hd.Generate(output, additionalInput2)
        if !bytes.Equal(hd.v[:len(v0)], v3) {
            t.Errorf("not same v3 %x, want %x", hd.v[:len(v0)], v3)
        }

        if !bytes.Equal(returnbits1, output) {
            t.Errorf("not expected return bits %x, want %x", output, returnbits1)
        }
    }
}
