package sm3xmss

import (
    "testing"
    "crypto/rand"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/xmss"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func decodeHex(s string) []byte {
    data, err := hex.DecodeString(s)
    if err != nil {
        panic("failed to parse hex data")
    }

    return data
}

func Test_XMSS(t *testing.T) {
    oid := uint32(0x00000001)

    prv, pub, err := GenerateKey(rand.Reader, oid)
    if err != nil {
        t.Fatal(err)
    }

    msg := make([]byte, 32)
    rand.Read(msg)

    sig, err := Sign(prv, msg)
    if err != nil {
        t.Fatal(err)
    }

    // os.WriteFile("./prv.txt", []byte(fmt.Sprintf("%x", prv)), 0644)

    m := make([]byte, len(sig))

    if !Verify(pub, m, sig) {
        t.Error("XMSS test failed. Verification does not match")
    }
}

func Test_XMSSWithName(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)

    name := "XMSS-SM3_10_256"

    prv, pub, err := GenerateKeyWithName(rand.Reader, name)
    if err != nil {
        t.Fatal(err)
    }

    msg := make([]byte, 32)
    rand.Read(msg)

    sig, err := Sign(prv, msg)
    if err != nil {
        t.Fatal(err)
    }

    m := make([]byte, len(sig))

    if !Verify(pub, m, sig) {
        t.Error("XMSS test failed. Verification does not match")
    }

    prvName, err := GetPrivateKeyTypeName(prv)
    if err != nil {
        t.Fatal(err)
    }

    if prvName != name {
        t.Error("XMSS test failed. GetPrivateKeyTypeName error")
    }

    pubName, err := GetPublicKeyTypeName(pub)
    if err != nil {
        t.Fatal(err)
    }

    if pubName != name {
        t.Error("XMSS test failed. GetPublicKeyTypeName error")
    }

    pub2, err := ExportPublicKey(prv)
    if err != nil {
        t.Fatal(err)
    }

    assert(pub2, pub, "XMSS test failed. ExportPublicKey error")
}

var testPub = `00000001bd73ee2f0f79aca1531e303abbfaaac73cd7fd1a16b56ba9dd0367e0af805868c285bf7bcfc446c38179ca5967275176dd6aa9d00740df8342c981efc80973b5`
var testPri = `0000000100000001bb884fb3e52316372d3a9f029c43615dd33494e96175e0df291f6fe2064401cf169ba2f03f176d7684396153ee39523de5d5e931292ed1a23926a037b0198861c285bf7bcfc446c38179ca5967275176dd6aa9d00740df8342c981efc80973b5bd73ee2f0f79aca1531e303abbfaaac73cd7fd1a16b56ba9dd0367e0af805868`
var testSig = `00000000b97932cf15ea21a7300cdc1676cc4427c4d72fc1786c1fc57a0bd1956f58ed9fc098346eecf524dfe15f5b35fbbcf2d3289f6418f3a824139e5bc0a6766a8a611800e3c54e1e25fae83f4691b721d9753d36c57df6e68ea8c47e969d31cf2b9f466c105c1a432aca2f13201fe876452130686b1cd5923f81d90d76e51155a596ae41f1a712183d475065618dd7f0892c1b0da861b4de18ae9ed4f169f0b91b5d7bc8fffe28ab683180b01326fedb9cc11c40ab34664e51eb7297a665087a97b1a70d16b8f15fcc45b18b0feeefc7f58b75e4a88e1333cb08d4e8dfdcf23addb6554948b836266b49ef6d077a4cf063bfb08961b298063a22925aa257b191c94149d932fb00c78cc651fed0adccc02915fe0f5534d4d115e576ea5c204e00955986c2fe34fa9e69e079295c32ea603fbf5ca7bef00824aa9bd757691d1c544031e69de44ee328b51b478254fa1573a1c251853ff095cf420272e26799763b9bbb791082ee909317b96239332f5488f8006a8daa09298e816d5729372f70e5725b1d1c473f9d1a5ee4def66d6598631d54cb2a667ca1ad09f3309b70d3c5e6357da3c202f227f81f62aa9446c380da37c85a1fec03bddbf7292556189e4640ab8b51209fcb3bb5695cb8dcce05e0f6bda7a1da0c2b32705f91facd1a0855a14412844f6bf063eb38f08a3cbfbbcbb8dad332cc5ccf8a3119bfeee26416ae4723f4ceecd56079c1345c2a25d934a41fb2cc639149d4ea6fc61df23ddb3da4cc51de0aef515926dcbad18876f3403bb48d87741197f6c0d5268dbfb1c49073960d5697184f7163c28ce5175196e2d3d1c7e00e8265f3c56d67e11ae0ce4bf0a72e1f16724690725640fdb89ad6cced44caef1c2bed530d4ea9653c7add8d8a25e871c9c8bed0ac52349e4ed1d691527453515c16a15a5ce5a4c0155e382d3fca8c7daf6bdc5eec665f023b8c15813af748be1ffa064ea70ca3512163ec89cfab3f6335a4512ca15220dc0967c2bf2ab7bce51e5ab2ed11b30e24e15ff8be18429b2ff85bc5cf3f58132d68fd7780b36fed23defbbb4c9d4c5c2f0cbbafb54e637422efa58dff01fda3cdf8d8542b33be0fd7e6032dd1c32159d3b7efb68b6d7e25d32ff45e0b28bf43b90c9868e8c1f481f8ffc04e146229eeec554b2ad3749c0240f39acd4f070e06d272eaa3a16a86946c52aef77b70c9bb225045696db0d7607200381daeb55e69a3572fba708005625839a696796a1442dacf425747b1e3e776923334efa13d547806e124a9b73042050fde11f9d81118bbcc599cb7ff0fb2ec5769a6fb342f66cec4678eb572dc31791981a5a3f2e35c3a83f6eb49068ca29812140c1f3ee05d9abb015fb0c5e190339499e9216268366ecc0315ddc7d01b4e81dbc6580c4697121988e3c93dfce7bac67554b6dedbbdc7db63d394d78e38ada9ab97437aba05e6a2bbe4dbd0fea77bb576d59d32acca18096def3432222d4ffea2ba2b956ecbe5db3e81c02a7a9ded417acbd7158e8c17e35f013840a39f6759c31db18ea7c3b0e929e78f97faa11273f9595389e21ecb249104cc7304170b4f21509b0737419b44a3c6fa4e740f714e1914156e6d7595315e51aeaa440e3ff01f9214ed2c6fbcf0479a818724055a1803b9e091156381e6e19aee8e88cd6f1abb1ca8120f7d93417ec88a60ae2283e360b404066bbb09ba083072d045fdd6c3ad250d02808cd80cd6ba054d929e4dc50a7cc45a7b9aa0dbf5a5c4907f50871167fb12d7b6265e772452936402ec9d4c836ce71ddb4bbefa5c01cdae9c13cf3061d8aa40da77095ea2548bebab1acbc186bf8be18269fbb4b83b554ed3f080bc5fcf3dd61e564f513cefb903322706504e1cf4a5cac45fd28518ef6c83b31c826cc71ee8c330b8b446b46c4a39482b4e6e37fd69933775dffb08b8e5add9f939eec4a78c7b1d91b0130e0ea4c85c4e52ffae909532badb5b6990d48ef1a12e3cd911aa017375a32b26e0c94517655cc3545e45ca6ee4d19d2d83ae4c4420b95ee703f6f566747f2e4437dc095fd59da1a184054e059d5581a0d66dd39d2bcb04f237ff0d54e7cae4353d936851bbac5668111b66302796d2f5cb0d76342afcba1244df1a07bf434079a3bfabc7d70d7adbf0d3d35edaaeb0b33be33f739ad152fee139793914f671230c23e0dc6344fc302741fdaacefa8d9f34dba95bdcbf0df4d3590a6ff2a928bfe7d616e4eca8d694047fab354d1e08e66a0efd164ef8b25f7e98d63b1ac74821ff51dddce3da14010fe2d632a3d93706d791f0888e98e053995b27010862717c223a96d7ac7861d0aa99ad9561d5cc47283ec65eda553d673233e5f5f16c8490b70216408dc0d3d5515c5359987de98271fc58ba726ce8a67fd9edf10e06553d099f830b7f4e19183a8257db17f2fe5a208bcae20bfdb8f5871681c4d8310c2aa7e18f87edb241c68cb4a1369ca9da4dd62990ab3aa2cd305fa1fb24bc804f4604935c01ef4f5e368e4cf64d62a965c9d7d8122664c2f929c727cfcd280d4f9c4f563d0be543df9cbf3cb77c778f38ed1f63c43111e91ad40d20656fcb988c85613267c2b28bc2dce178e46062e120471b5a7ea94da2ac870f3cdc2f46c7df7aed4b915840ba4e36caf68a9118bf5c4c0531568cbcc8a5e556bfd2dd845953b33c446ea196106b67699d45708e1ab76439ed73bd977fb1348e8775f12de48146dad6add2dbbfd7165a2ae79ca0b2a2340b04db761cb287aa3e00126b2ff20f49a637cbda74292568ccc74feed9b66aa45a590678daf35ca42981748fcb024b5942f58d5b0fa8f040bef9a57e504cbc72836b428b7d083aafb9593644b1d5df5c36644e25cb33b5bb7b536184284bf2b2e23c267763694f470c7e6c35b6ae865acc6c191dc4b0a9b6bad6566cbc73146f2a82f85e08bbfb6947f182c933240a640b65fe8bc2df59029f01c93bb22c88a08beb97f86e6a089201ef86427f6dfdd291e6704a0c3c25b955fb158e64fca6c83299045abf0e5451c8441db23b28c16036fce708c1970ceb5e7bd46521624f8e8f76a812d5bf8da5a5abd3d7bd5f099ac55f60809599416a2d72efb92e667deedd34ae47d7384c0357f4e964baf487f041dba84d30d762ceaeab3bc001337084c135754aeb5481ff77f3fd3c4a8400ce445e3ac6b1c29c5f13bd496c2dcd6773c7b5bcc21554fbeee86b1c61dbf37fcdcc2fdb1246c6a47e44b19f7316f7122c4c0b9be438cdfec3ced45d2faa23cfbe6a2727014193844b9dece2dea2ed7ad1e51331880ab86a6e7d0e59509f7a25adc3f53ed7b195529de2e06a5a8278c2d314665dcc02f2910f767769d56dcf0e8246f88aeccea5f0ea7cb3ea8ebbab35011b2b37000c64f002c263228d1989e2a3cb56b1e2fe3e2034ba60b94e6b598de0ef738dba9657a75fa2597fcfd07c2225b934048fdfaa67b4668a2f76506c0f14b2dc1ff99f1f270fadd716bf61732378dfcebd37997edb53a43ea59086b3ac4f45318d3c78861ab4923a44d80ce724874ff67b8c0efc6e991eec58e9539d8d2c767a1a4b37f3`

func Test_XMSS_Sign(t *testing.T) {
    pub := decodeHex(testPub)
    pri := decodeHex(testPri)

    pubkey := new(xmss.PublicKey)
    pubkey.X = pub

    prikey := new(xmss.PrivateKey)
    prikey.D = pri

    msg := make([]byte, 32)
    rand.Read(msg)

    sig, err := Sign(prikey, msg)
    if err != nil {
        t.Fatal(err)
    }

    if len(sig) == 0 {
        t.Error("XMSS_Sign test failed. sign error")
    }
}

func Test_XMSS_Verify(t *testing.T) {
    sig := decodeHex(testSig)
    pub := decodeHex(testPub)

    pubkey := new(xmss.PublicKey)
    pubkey.X = pub

    m := make([]byte, len(sig))

    if !Verify(pubkey, m, sig) {
        t.Error("XMSS_Verify test failed. Verification does not match")
    }
}

func Test_XMSS_UseKey(t *testing.T) {
    pub := decodeHex(testPub)
    pri := decodeHex(testPri)

    pubkey := new(xmss.PublicKey)
    pubkey.X = pub

    prikey := new(xmss.PrivateKey)
    prikey.D = pri

    msg := make([]byte, 32)
    rand.Read(msg)

    sig, err := Sign(prikey, msg)
    if err != nil {
        t.Fatal(err)
    }

    m := make([]byte, len(sig))

    if !Verify(pubkey, m, sig) {
        t.Error("XMSS_UseKey test failed. Verification does not match")
    }
}
