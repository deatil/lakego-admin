package kbkdf

import (
    "hash"
    "bytes"
    "testing"
    "encoding/hex"
    "crypto/cipher"
    "crypto/sha256"
    "crypto/sha512"

    "github.com/deatil/go-cryptobin/cipher/aria"
    "github.com/deatil/go-cryptobin/cipher/seed"
    "github.com/deatil/go-cryptobin/cipher/hight"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_CMAC_CounterModeKey(t *testing.T) {
    var got []byte
    for idx, tc := range testcasesCMACCtr {
        want := tc.K0
        got = CounterModeKey(NewCMACPRF(tc.NewCipher), tc.KI, tc.Label, tc.Context, tc.CounterSize/8, tc.L/8)

        if !bytes.Equal(got, want) {
            t.Errorf("failed test case %d, got %x, want %x", idx, got, want)
        }
    }
}

func Test_CMAC_FeedbackModeKey(t *testing.T) {
    var got []byte
    for idx, tc := range testcasesCMACFB {
        want := tc.K0
        got = FeedbackModeKey(NewCMACPRF(tc.NewCipher), tc.KI, tc.Label, tc.Context, tc.IV, tc.CounterSize/8, tc.L/8)

        if !bytes.Equal(got, want) {
            t.Errorf("failed test case %d, got %x, want %x", idx, got, want)
        }
    }
}

func Test_CMAC_PipelineModeKey(t *testing.T) {
    var got []byte
    for idx, tc := range testcasesCMACDP {
        want := tc.K0
        got = PipelineModeKey(NewCMACPRF(tc.NewCipher), tc.KI, tc.Label, tc.Context, tc.CounterSize/8, tc.L/8)

        if !bytes.Equal(got, want) {
            t.Errorf("failed test case %d, got %x, want %x", idx, got, want)
        }
    }
}

// TTAK.KO-12.0272

type testVectorCMAC struct {
    NewCipher   func(key []byte) (cipher.Block, error)
    CounterSize int // bits
    KI, Label   []byte
    Context, IV []byte
    L           int // bits
    K0          []byte
}

var (
    testcasesCMACCtr = []testVectorCMAC{
        // ARIA-128
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`fa0317cb4ec773e1b5bb021b6dd892f7`),
            Label:       fromHex(`43231f09aa4d88b6233d6717132c6a273f0032b81f0a07194ec652c02736bf7e163b05f3b5dc9fa29aedec2186224fca9500f3872b0752a97cdcf052`),
            Context:     fromHex(`31b212c8928abc3c455ea68c5ace97a82c92aed394333a74463e888460df2b410d9a361764f261d6582c337eb6bd3941102d8b7d9d582f4a57243399`),
            L:           0x200,
            K0:          fromHex(`bd6b11cd9c272b32e1febce4e7caac3ebd7fed3ae53a77ac7f4a097656357d484a2fa490e67d49557256cac9ff9b9b60f7d544985f053a9ba2dc5b187cb142f7`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`cda2ab4a91c1caba26e755a83d8ddf20`),
            Label:       fromHex(`129358c99a1f6144eff0462f72f3dd4bf27d9d0b43578c3286533c249c883279d8ca4d7d12d329f66c85908eac9e52a25fcadb6a0f47b65e32c7b42b`),
            Context:     fromHex(`8a32472f8c9edcf399b896bea7ee7727b3e8870f8b4f708bdcd3e20738c1e63f6505b9848084c026643f357e2e1ac8c13a5178e5b76de7638c13c2e4`),
            L:           0x200,
            K0:          fromHex(`9809d6df77529f7e15e61a87d88362c525d0685206eb4a0dc2cda5eecff7b18ca514561b9e6fc03dd36a8928d4c672f86d7ce8ed5cca62ea9fa1550288097949`),
        },
        // ARIA-192
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`79b90534f31516fafeafa9db830b8a3b15781056f22713a2`),
            Label:       fromHex(`767ab85a5c910130cf2c82cbb92d84ca22173b9eddcb9d10e9ff02b8fe4588544d356071bb410bfd831ae13cb53d2590419695dd84a6551d55beeb84`),
            Context:     fromHex(`462a69a5f744f3f89ca81726a056d2e6cda5df668f4470825d2681073d64388a8b18a780aeb2b6633c5f8db29e2642a34f0eb74d055673f69e69cafd`),
            L:           0x200,
            K0:          fromHex(`8ea637b83d368a34be920374810e971605122b088fa5dadbac04dd9b7a60fcbe0f92783446fce8937afac473b6c1447be626e2e34f06c6202f27122f12352859`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`b2d776cb982fa2310039c4d2297f4529452ca6c7e28720ef`),
            Label:       fromHex(`a97a4fc189073beefcbd7406c08d4148b8bd4f303b96fd076ba031a819db3f3088c70e2ee5462f5c99a01502f22f599228be2390fe5c22dffe83f977`),
            Context:     fromHex(`e49e1cc48d2527ca679a918fcf0c61a128ae68de97a705f0a47a2f7b667815d1fc64bd9a5710a6b3236dfa558a55852bee1353709ffdb180a1997e08`),
            L:           0x200,
            K0:          fromHex(`514db53eadc31980063cc381390ea5b3cd598525bb333449afc3b6b6d8c2def41a625a2173ed32e8b88907f499ec3886d21fc45a2199b00dc3a0c14c720cf00a`),
        },
        // ARIA-256
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`b73bb3912b3be6192d632889e2f9fb4468ffe750d9a947a4ee4749c4f4953b46`),
            Label:       fromHex(`25bbc3a5dd65a0b34726216415341e538761f11f2d0166fec127eebd61b0d94ec6032621198c75490b86566bd9a6b4e11985ceadd6b4e40c1932cb52`),
            Context:     fromHex(`400ee1a7d91e24af85cda45afbecee21cf01a8831ce7d5317d227a4be182d83ed9f800d76465f73b53c4e1ce719f60e7fdec70a54f4e313dc1a8503b`),
            L:           0x200,
            K0:          fromHex(`265fd0179e3279e879abc0d1f7706e325f7f21aa68abf2ec7dc29bc7362dcec6a72de4788ad0a99a2ac05094ef81dbeb687e3c526553908a838289f3cd8583a4`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`b073c6a26c12298d151e5b224c77faf6884081f325469745594e1ff547a1b765`),
            Label:       fromHex(`92698ad4e787b3e0acf3b47df530985f08e36caac56b6f8734318f6bcb60b9de519b0fc7394609aeb6e7eaaccffce40631c0fa9d11918dbd3ea5f9b1`),
            Context:     fromHex(`8b03612b4431e5b0eea25e12cafed2de4af08b5701a14128348f1fc70ecedd7e43ab97ca0745e081e6ef9e2ddd852affaba2f64ab8d66b0f8f7ff45b`),
            L:           0x200,
            K0:          fromHex(`85321fd2bf37b5334048795e8a590dc6f8f5f3a07b2cce630754a25fc610b2f14be3bdb108232852236aff23170c56dad0d2d60aa3741c71e3820f87812eb85b`),
        },
        // HIGHT
        {
            NewCipher:   hight.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`bb0e90646aad5ba088fda90a52b2d304`),
            Label:       fromHex(`6e4236aeea446820ed0284b0addce602595aa4b1fcd13e3983af76ca7b4ac275ce5f1e9680258c3a96628c936421c134c1c38adeb80f75da8023ba01`),
            Context:     fromHex(`496b7b4717b02012bdc242cf5e487eff3e68b4f1e53913e22d203cad0b73de596a629a8779d5b9be060d929c87e1236610beb2ce2463521b95f2f75e`),
            L:           0x200,
            K0:          fromHex(`36f977f7c8619c7d7dc5a9f8ce35d1ac945d12b6d9931f4566972f6d5395304bc5cf6d9841e9380c71fce4708ae5200aeee1f125ea6106ed69e21b80f902116d`),
        },
        {
            NewCipher:   hight.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`c13518447632cd6a3f2b2945c38ae57c`),
            Label:       fromHex(`133d79a8d4524c1dba38626fbe622f27bd38727bb2b3af80794fda1b8047fe595419c3ae8f21a20952982cef4121ce7c3b6c5cff17a7bfe6be3dc70b`),
            Context:     fromHex(`73fa89538915a31270d30e0e0be5ddfab04ebe0187008db6d7109872ee6b145d2892739d83e6d378012f4be13e11c5b62bf18fe2138f87dc79c0af16`),
            L:           0x200,
            K0:          fromHex(`b392e26af25522e817b5b8fc09e112c3e0f92009f439285d1ef3ce1b4cd3fe8cbc6c8fff1eb49e2aad36d54ecd1235a534104906d78469c1443408ef1bc589ab`),
        },
        // SEED
        {
            NewCipher:   seed.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`d899a261ac0bf40b04f110681b8859e4`),
            Label:       fromHex(`8ed363214d5ca03328964b636a889f83850bc41af69ce426d080490cf57465514ee2768d47fde795fad82ca919ca1c9553122d8017549d431ddd6b0a`),
            Context:     fromHex(`b78e81454183e6fea2de1e842e0b782433fdecc33f70b60279b9284fe02f6df2517faffd9ac52c1ef442fc1145deee1edc53f55ffcba9ed9fe1087ca`),
            L:           0x200,
            K0:          fromHex(`762dfe66668c7807611e8115156277e595597320b22c2e25881f1bcc292077166a39dbe9aa75e05d57d1f5d69f286eccd3d7e0fef68b3e1e88d5cd26f85ab7cb`),
        },
        {
            NewCipher:   seed.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`54445b756402f067c3955d70d3bfafdc`),
            Label:       fromHex(`f2f63d0be2fc8a4b26f1f723569f4181f3a1322d4b43a2cef004cac5f03672321302f4779291e2c98cfadea0780fcb6c62d0bb8e32ebfdcdc3181c11`),
            Context:     fromHex(`a26665d4b8b6ccce0dccc79851861052cf78449ea724d53a3a780e8eb35101c8708bbfcb47938d7a1806508b4a4960a781eb6d89fd730869b8fd262b`),
            L:           0x200,
            K0:          fromHex(`699e7450003e2ab7500330eb854e09c4ecd2d87cf54cd6b780eb50b36d1756c01391a1b839e090c960c183427abca3954f8d137d08cf4a7ef8cd7d5da7e2a7ca`),
        },
    }
    testcasesCMACFB = []testVectorCMAC{
        // ARIA-128
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`33b6fd27d8744df0db928827fa6677b9`),
            IV:          fromHex(`d42bcc8bd0866bc5e6758979753e54e9`),
            Label:       fromHex(`b9f5de570139e6eae8b22cd888b90973009fc4be979934d3840f726a09e5a8689b0c18b5603b619cf61cddcfd02383e8132bc938023b90dc5cc2d3d4`),
            Context:     fromHex(`cd6424945d9af9657447474f11d0d13a461b2c81151ac26c087376785965556dd005a171908b0bb86645d34a9cc5296dc67cc656102257587b8ecc58`),
            L:           0x200,
            K0:          fromHex(`d05c4264067051fe53c6381639f281d0ba124e0a4ce8fd49db399ef498a1cee996cf553f84bc37bafa3ae5b789347c447e3b9eef6511692c361581a9d9713110`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`c33df77be674bd658abf9ce0d17071ed`),
            IV:          fromHex(`c73a79be0fa9ab5b0dd3d0016b998ab1`),
            Label:       fromHex(`f029d930b7902bcbdb5acdd310642b47edf530761e53cd29001c1557869734bd531957233482ca435f3fc09deacb9556f4078f8a3e51a84779512183`),
            Context:     fromHex(`b1ee0ab44fc173e13d9a2c68eaaaf40e0be587343823f6847db0026ef7125b51bc6fbae6d075c02fb8bfc90a0262d5bcb7c777ac1362fa68f8aa7bc0`),
            L:           0x200,
            K0:          fromHex(`50f65b5c84d7c9f92bc31b2be82b0c3f4d0c02bd049f7f8677d243742dd54154f26c45a4df88f0e211737411aa19248272b51b02cfff8e1d87b498035053bcbb`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 0,
            KI:          fromHex(`e8a5af1eaa3be23ce1c2374ac6ec1768`),
            IV:          fromHex(`7b19e15ee649877a35cd0778f4fc8059`),
            Label:       fromHex(`f6f418a655d582e5038888a6d8c06e83ff9dbcf21abf46340979ebd412a9ba3911b46973fedc6487a0ca80248b34c6367a3e8027a694924ca3370f9d`),
            Context:     fromHex(`63c883639176ffde77cfbf50b76ea65abfbe0474ee358ec51b402bf0fd5a055ffc7abe48563dd338f3d5ea32ff07a9299c537df8c0d478d21be1c317`),
            L:           0x200,
            K0:          fromHex(`528d12498323c182e8c3a2b8876aeb7cf6882f892efb64113c746238b68874369f4145a50151ca0bac1ca86c7833cc6b293250e5f3a6bba7990036ec5c7edfa2`),
        },
        // ARIA-192
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`a6f3ccef5e8445953a585592896d6bab35190dd2e57f90fb`),
            IV:          fromHex(`cf0af591d90434b68f0b68b012147b24`),
            Label:       fromHex(`857af3e3819d6ece674e2f1915886acf59073f58b7c09042546591f6be7912185c7d4bae2f29e68d4967944a7e18841470767721d753188ce28a655f`),
            Context:     fromHex(`2787be4dff233ab3cf65ac982da7613c10ac3d243e1896949ca92169b3b4d0bb3733449402296451b149f81d44f2f1653f9402545e61b354c5097f6e`),
            L:           0x200,
            K0:          fromHex(`ea66baea7288e1d1441482eb6c9bd155d9e38c3c2b5618b44726c468d563350d795ba522b66c2dcf62fe3bf24520903e6bff5ddc346cc0a9597c13a8ca7929d5`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`7f6630090c078be6d2bfecdcd88182918bd0fd6753e1d570`),
            IV:          fromHex(`90201cf67a2ba19b3ee9fc8f0d692342`),
            Label:       fromHex(`3705136adee8c83705509495f9082540ed7619a472e8081bbc5eeabe5e03c55bafa866aaff1eb6934393555b307207a739e82aa0918b87e369679d86`),
            Context:     fromHex(`df34b79b89ec3e694c66c1285998bd5effe8a0bebc364d99f5ed7b42cb99a737f76babc3572c0ef924631fdf7af2cd658765e217f565eae823433471`),
            L:           0x200,
            K0:          fromHex(`be8456a62298fc16bbb4a75b614ff95261da45c6a8f003f0f2cad01d2bac34e3275ed0f1bd9c83ac797ffd3f01dafd73071fa4580408a239d83adccdcb470178`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 0,
            KI:          fromHex(`401dd9923cea5b6378fd04ce04007d3474a11f9d69e9acfe`),
            IV:          fromHex(`873250ae15d36f6d583966680c76cdf4`),
            Label:       fromHex(`a2b2ca637fade4fbc3359c4ee80888524d40e189d456f507d66da7651bd519346786e52e0c49f9e7fa47763355b90c60230d6fe4ed4c681a23f07f96`),
            Context:     fromHex(`2b7d460075a11839e918a0d298b62b73a20b08b106f858fc36bd65818e30d33b69e74f99f8d3aea2b128bc5bf2c4f2c9334dda9c2e7a7e8b092572a3`),
            L:           0x200,
            K0:          fromHex(`9921509cb4397223d33f82bcb9ff3245b5be1f599b483831053268b98443f7a689c2a7d19ba22b0ad885af28e2d4f7f1e2e9dc9f16e1618c837b5caee393884d`),
        },
        // ARIA-256
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`6f365b5f220a854f65a285a29ecd045e5aefe0b90e019b09fb47252cf753d6b1`),
            IV:          fromHex(`44bba33cc2055a79cd4db3537d20f417`),
            Label:       fromHex(`4cb4c8baefc3e1fe6e8ffccb6891610a087a58bee2deb43beb0a31cd1a1721736a8bfbaaf9a2c5fe0dcc5fbbdfe3bd40322ecf5082a770c3cc4f6d0c`),
            Context:     fromHex(`35694629b75284f27001b52dec900980e4c7655bcc3fe67cf2fa537b6f31109bce9bb5b98dffdad4745d7a094a8ebdd4d049209b6b5f2eaa61a23dad`),
            L:           0x200,
            K0:          fromHex(`16e1dd83a9dc46f0207962e2226e1e392dcfed6ca1ad45c71b32db22c7bc4399a4007eb976d54297f7a43465cb821e94de290d0a6809276f1e544c85aebf4d92`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`a4f30aeb37a6304f9db28d3631884873babac49dd24887d9e21a8b65fc73a8e9`),
            IV:          fromHex(`7aa1c9be2b93a1b49a1691925efe63ba`),
            Label:       fromHex(`6391b40f0e805abb8f3137fea4076dfbebb76f3fb0f14d9a52a11dab4ead116ee6f7f58857025de4eab43fbd6e2da8a9d00f45f777de3d10595c7c01`),
            Context:     fromHex(`8bc92aa3ead3d9fedcafb7165ea967256876d6cf3c22d0244128a7991dd9bbe42d5492b0d39a44aa2dce4ad64da007615de18a56541078075b081f67`),
            L:           0x200,
            K0:          fromHex(`6e98abe64e5653120f1c47503f6ce0200c9b3fd878f26caaf11af372b155c9fe54ad7850c21c1488bffd9b92df780d23ee43978818019bcfa84735e80749a151`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 0,
            KI:          fromHex(`539d74308654a7f42866f174cfc5019072b75e261f200bc178c02b96077c47c6`),
            IV:          fromHex(`6f100ea4530477afa27f9cd7838ab324`),
            Label:       fromHex(`2e49fcc88af112e847d3083316c7d749d9f1b612ed74803ee787ad128927795b61da6ec3b5a19356e5768bc6ecbc7254cc0889a2e983b648d8197a8a`),
            Context:     fromHex(`7c32f0fac2bd47bc63db832b0adff6e92abfe5fa6e084db2daf08ed8a8bcdc917bc8d49848204b015cf8016c1ed15f89085da1932fc4c60437aac26d`),
            L:           0x200,
            K0:          fromHex(`7497a82466256ec4e79d9b0f5713fbd8a9f198e434f8e20b5d607d957e57ea50feac1414c9cca4e176691c7eadc45a88bc77f52323f513911c3e248f15be21d1`),
        },
        // HIGHT
        {
            NewCipher:   hight.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`d11f43e61e5dc7208b9e463b0bf1dae8`),
            IV:          fromHex(`1d57ef5d80ad66ff`),
            Label:       fromHex(`a228b86372682476c6b246c264e8ce5d946a4346d2a92d2ad05c623304c5134e4d0790150ba79140ee0e4a25f9f359fdc4ea52023ca75e7ea1815092`),
            Context:     fromHex(`52e59ac33b9bd8ca39fd5d22b0631ff5048ab69c21aad1246286d7463ed260600932fe8683edd51bf0fe41f8e82878b6a3c3a9d6580c883fe7619544`),
            L:           0x200,
            K0:          fromHex(`9a4c467868fdecb0976622e7f24ae3e7604c90de037a038572b4c890dc8fda1fa6fee5590c5410d8a3df921430bfbac0ea917298b51e2f0b4a12b6eb8e9bd17f`),
        },
        {
            NewCipher:   hight.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`a9176aa3f756ad8db62b67cc20eacf06`),
            IV:          fromHex(`5ebe826bcfc1e940`),
            Label:       fromHex(`c46a4a1440f70f676b6e637f74d6659389a98f8a9c7931aaf8bd72f789e549ef1a89ed040bbad5cb3489570183987a0be4bd3df8079d5cd27a813f21`),
            Context:     fromHex(`50563a8091d297ce71cd61fa9f47992c7bc3bc1287a2e42b3448c9501782f3a24b8a3503f77a1928b08d2f2bc07c99cd55e25891b9baf7dcc3597401`),
            L:           0x200,
            K0:          fromHex(`a6a66d9c63f6f02d4742fe8e578b73096b6c6b43c75fbd1a7a0a7c758436f2d3cf5ade6c9aa11edc9c0486cd162052ed3807669553d82d57c866e8f2596bade4`),
        },
        {
            NewCipher:   hight.NewCipher,
            CounterSize: 0,
            KI:          fromHex(`e829c6877cd71ac0a2d8f3d33c956c96`),
            IV:          fromHex(`dde6850e4ee9e2ac`),
            Label:       fromHex(`4595366224dd4a17b27466a6b570f9681d9889bd922b605b98301e66a87f714ab35f8ac8d1b6a064ff9e18bf24b42eb6d47658e333db6e24574fd30f`),
            Context:     fromHex(`a5480131327522e777cc7b0ace19af866e092b22dc3d061d4989e7cc3a8968b7d659f91d1380c74c82dae4d27ce26deb83bf9b32e2cd263133889339`),
            L:           0x200,
            K0:          fromHex(`2ae235eae847fda1b53dad269ab1392a0874867852d55bbae8cf3ef1d8852742369ed44f46cc22e3c7938acaad0341e0c97d349d41c54d756f52c84f16ddb5c9`),
        },
        // SEED
        {
            NewCipher:   seed.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`c0ec404a828088e5f79e2840b4dfda41`),
            IV:          fromHex(`9e3ef8ab426d06cffccf9e7b016d4981`),
            Label:       fromHex(`67bd99e57f8b859fd13b89a0250b945a9ddb7408d85e8008daea9cc1a57305e639f1550f5e2a8cbd9dcc368c4391759e66bb332977670a237cb60753`),
            Context:     fromHex(`ad7d03f1d618fe349992a3be3a3c8641799da4f937169e010fcf738614a6ca2db04312c1f592d9fbf409f789227ad5c5b4f6c587baca990fe28b8c9a`),
            L:           0x200,
            K0:          fromHex(`3c6dba1fee26203c0d221826148013bafe5ab7886c59420e10870ff241e6a8e0525b31d62d6907a4233104c03beb06b9511249ba4b9e327d0f56e546180524fe`),
        },
        {
            NewCipher:   seed.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`946e187f62347ef6f71714a42174871c`),
            IV:          fromHex(`9fa4e7e0bffd91188aa50645084eb48c`),
            Label:       fromHex(`c804f05f5674aa67b09f9959c0754e87697744f9b554f3dd16080ee75235f890059f0cdfcdae46610eda6a8ee21aa8d24c8029c6172f2ba13ca9330b`),
            Context:     fromHex(`e42ff85f49551f54deaf634ac9cd79e0d3d9da67bcaeca667d26254cb8e3b783e5fe825d8ee2f710cd83956dd68b076089e73aedf9b6c528a07532fd`),
            L:           0x200,
            K0:          fromHex(`2e607bf7204a8674017b6875709e9397f104a80e7585eba571b0ee749c3928f937a95a5b0e596e13f2e11c7e02ba70915f69ebcf6bab812654d8dcc731fdd2f1`),
        },
        {
            NewCipher:   seed.NewCipher,
            CounterSize: 0,
            KI:          fromHex(`66e187fc7047253206d122f4cee6d62a`),
            IV:          fromHex(`c633570173079aa2edf10d9e9190aad1`),
            Label:       fromHex(`a468d915f7a5788625764636fb61fb1d2e9cfe8f4ebe8a99a21b8c002f3dc2acdef7d6756418f666e00ca9046fb8af2eb1e41c0a9f9b218bb2a12f40`),
            Context:     fromHex(`c47374b18963c75362e80b958dca631c1565b6f67c03df6b4d819d0cd948b5a6390b86468b7c1c00154dd9e95a3e8b67ba4c68a1d5635134449422e3`),
            L:           0x200,
            K0:          fromHex(`e127cc1264a0367ed2f797d5980e91d2a3c79fcc765be9358a6071bb34453acda8a2245b8ebd436ee51d64dc91c6cf57f8a99699307b8a8853603b6aa705bdb6`),
        },
    }
    testcasesCMACDP = []testVectorCMAC{
        // ARIA-128
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`e9d69cf11d994561cb44a4d287f47027`),
            Label:       fromHex(`4742592ba10bd2fe1c861e140aa689c6d08302fea12a51aa0312e18219ec7a536059e64de512cd2d80e35434c9cbb6cc31b89af357a7cd2a61860aca`),
            Context:     fromHex(`78e16d721972459c6538e0981bb2edd42143700bf0af2e11612077e42bf9e1cfefda6cac5f6f1fa86a39eb9dc2a2c85de90065b96f8adbe806787f19`),
            L:           0x200,
            K0:          fromHex(`25ef9ced759d0dc8b2b1a1703aa670c2eef56807fde63349f37837ddb867fb4a82a144f24616cde7c85ab4bb7d46bf6db948b9923366bd7351e4993d4333f284`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`5674f7edd70f68c88ebe43b8db09c49a`),
            Label:       fromHex(`463f13b7e9de09f664e5cda1491b314b17c7de7536f797b76f3b2f56bd85fad8157cf40f830840216aa05831f4a9c29fc55ffc5219160a890921b150`),
            Context:     fromHex(`1c7dac079781f8cfbc3b9f6635837779bce6155b67d3b3c00dc9ec6a408bbe194190d6af54a892f9e5a181906c7a9d5e0c7127c79c25fb2d1a84b4c7`),
            L:           0x200,
            K0:          fromHex(`aaf4e7c3b237b162af54f351835f587f361b28aa365ce84009e0ac1acf50edc287a0bb0628c47e9261f030bc5bc1e6628d390231cabed57357593d0700a9a162`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 0,
            KI:          fromHex(`b531b06fbb2efd59d6d291ccc986b5be`),
            Label:       fromHex(`1501a06c5146b0eae2f32124a6115b1733bc37c72064ce26a4f2d84429211bd78c2f1aea3bbdaafff312361eedf2124595729dedadac2417d20d6084`),
            Context:     fromHex(`169d76adc88e14d3a97cd0a26062642544115b498556ac345911be9d28a8db5602e7e5974a40bd71f825984ab46973d230e50ba19a51d1a956387498`),
            L:           0x200,
            K0:          fromHex(`14ee0e2d320fab318092a509c68b4f746f74633c575d9668c5610a143eb962854793bcc1c8d31d28964de3d012af55068b41dca937a7dc1be67973784ff87318`),
        },
        // ARIA-192
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`224c70fd148861536ac4ac04b3636517c0182a1d5f71a4be`),
            Label:       fromHex(`8e1c56967ee0e8f0c77d54eb17f3d202f74b5bc49fadaed9fa54176edfda23f714b173ad249fab163fe4efa3b845360f63e39a228013c09a37a566ac`),
            Context:     fromHex(`53054d5c7d0ecb2bc2467f226fd2689a6255f0f08a56a09aef2cf231e4d6554531a93ff5f17d15f74aaa3ebb29521bbfba238eac30531cfb8a45d6f5`),
            L:           0x200,
            K0:          fromHex(`77feb8d322abc599c966caf4e38855a0f10f67ea3559a6f7b643e5f08fbcb749027105280002754dae3c0de9b86bc9d79ba0d2199a11696b24060117b75322b2`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`aaed815efb067a067fdcc3a0fa6c8e020566b5055b0920a3`),
            Label:       fromHex(`4513abb164a1574c32ed29e6b07740e326739d54650c540c5e0afbd6d6bace91c8f42c425456324728756fba904949196670ceab8fbbe4ca671a2fc7`),
            Context:     fromHex(`f751948640e38d0b3a4c97bdb76ecd0c60001f41234697a0a83783ec395e6a872cd8c69569a8d8672d79743f3e1402ddd7e8be32b51f7742e68f8ee3`),
            L:           0x200,
            K0:          fromHex(`39c63a8c59075726b5cf46ae040a57e737138d10278be5c2124b07e51c5d42181e0d91b81a8dbcb7d107c1b62c42448bcfcfc1e5ba8fc128c841ded55ef53457`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 0,
            KI:          fromHex(`a83e142bdb7137cbfeb1b9c7a3dd27f4c6cc8d83cadbe69c`),
            Label:       fromHex(`b4cf4a4c9e31e464f0ca6c71ec1622d4899ee20a991bf29e7889869d3f166774b60264337f97268590689a07590cc8ca14d9f8e592928c4739e12605`),
            Context:     fromHex(`9202182754f02023513274c358c8af9fd34aa7f34deb75ed69bb2fa243ec652eb3bf5fa18bfa7e530aa45f3fac85b5de491560cf7e1530650316b6e5`),
            L:           0x200,
            K0:          fromHex(`33703eabdac09243cc6260a3b17621952f5be2a76b88dfb8325ed1d013282cd143a48a14d81cbd2f51ad589280dfb2c7c1951261caef15f25334872419051703`),
        },
        // ARIA-256
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`736eea46389a3c0bdbc95ca2bc2ddeaff53457322aced461f5994c7176db6c96`),
            Label:       fromHex(`97c545be0b5faeeebada5ce51d046c39210962a9acac6599ade7128c359db3513bb130d8d738317a3dc03a160338da84a6579a7e470e16676a23fb04`),
            Context:     fromHex(`7aafe2abcff9e4e4f349a6818270df2c7343660f4cdf7675f459aedc11acf0fcdec23bd482befdb2da7c4200b9f85554511e54b8975aaa6963ae6d85`),
            L:           0x200,
            K0:          fromHex(`e8438d327a101f32f520482487753e7ad0ec1430686e772e39e145933332a0ca44a86a550b2d10ec99d531635a30f55a6b692b9e3518b105e03d4370d2946ebf`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`6d7be9d5fbd58a3d23c3f12b6cb425a29ba5e5ab460860db6ee775f04a8cf628`),
            Label:       fromHex(`d70632637b70d400d0fa1d0f0b3dd15348098a85394bbc1dd5480eaeaefda22346fa64409f37e14f7eab965a5683e5c9772c886629120c379fe73ed1`),
            Context:     fromHex(`9f55992366608b2170636928aae5716e781f08e819f0b65927553942dd604ee5ad8e871067aca5ea6980d487c09d091f2a7a4c1e3f449bb7fec8ff8c`),
            L:           0x200,
            K0:          fromHex(`97b01e6927b1bedcecc022f0e1528e80b6983fd74bbd4a9bb44a8d324577f93b449e16c14834f10921faecc0ec2a37efc3f2a1a1e67f8975271647eba924ba0c`),
        },
        {
            NewCipher:   aria.NewCipher,
            CounterSize: 0,
            KI:          fromHex(`dda4127e9ff8b25ebb021c4fabc5436818058e599d96e0e91bbdc68c388b2955`),
            Label:       fromHex(`2cbd26f5151aca0f9d724e0256372a45f653eea2bef986f92a49079d6eae33c59d32a2a655084cca5d6c92acc0c1b386609bbe9f383d5e5960f26c0b`),
            Context:     fromHex(`c2bf0f7e536707c37e6cf809fe0672c079cdd957f89212e97da08c4d204083eb15429a7743e9a2d7894d23575208edd5123a1aad3066c2ec483ed87d`),
            L:           0x200,
            K0:          fromHex(`bc38752832938636f19a5727010ea2d91f0eec3030cd39d0ab3a7e7dfdf498170f39ff8cc6e1cd680d539202104b57e281d5fb011a8b07962272696610ed5b77`),
        },
        // HIGHT
        {
            NewCipher:   hight.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`be2b8832ea5e6ed664afdea6040b5fd1`),
            Label:       fromHex(`ab71f520eabf37cb8448b49c4b383faaeb989e10de0d20ebe41b1267f9209387f212d50a3c10fa0736e9256666205a95556f17ccb8069d03cf403cf5`),
            Context:     fromHex(`c7cb3b9c0d11c98f49a89e011daae04c9ec258d6dd59d3987592d178d9877761f7f7084800c184ac7fb509930d2c4f333da7a8bb9fadc87e62c63fdd`),
            L:           0x200,
            K0:          fromHex(`790a7716d70fedff842cbc8ee6ce46e8b51b7d159a9af177559474f90242cb3a239cc4ed57b121578d6ccb696e2ac90fcf522dcab6ce07e5d0e5a7f9abe96d07`),
        },
        {
            NewCipher:   hight.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`4c1d15857641d72811b3783d47649f52`),
            Label:       fromHex(`7c026b1aedfa51837c786a8b9c25db7dd06567ac2d7ecb12a36f54bf1a3919ed83e627177649805860ff3cc7451dafcab5b4eebff13d39459ad90780`),
            Context:     fromHex(`2de78ba52ce0359cb07215c1905fbf947c6a304edb763ef991f1bd6c67b19abb3378275c47b678a4a803f69eadd4236ccf48006871cad95942de2e67`),
            L:           0x200,
            K0:          fromHex(`c45ddd2beeea3401637804ae45b4c39bc20aca788e6176415061a7f9b4bb29efd9d3d75e679464fe7224102dfd8778136df4f92cba1bde57dbfd5f453ca4c7e5`),
        },
        {
            NewCipher:   hight.NewCipher,
            CounterSize: 0,
            KI:          fromHex(`3c3b799a4ee15f23a06dc5e4d1cf5069`),
            Label:       fromHex(`1fcb1500e3100c4ed4b93d1e896b10f68650cae5f11cc9ebf505514f21b240e65672d4e0863ecd020622c372fb428a8c8f555d4721f948ea6ddeec67`),
            Context:     fromHex(`56d0e5fe6c0c37db5380856680a5b4e13eab4c0aeca321985ad0f761a74bd3f4f341725ff12ffbc271b2e391f4e7927dbff4ddf1a66ff571460558dc`),
            L:           0x200,
            K0:          fromHex(`8dc929b4099e7694c29fdba26f5eb70a887f76e71a3d5773444d2ce0d9cbda6a29c315bbf7b40bfbe6433c8ada47d1a2b599017943fa3226693c5ee0226e4f17`),
        },
        // SEED
        {
            NewCipher:   seed.NewCipher,
            CounterSize: 8,
            KI:          fromHex(`5b898cdfdd9b46a8e3f8e5edb79247c4`),
            Label:       fromHex(`50db604f57ac1864fb19657a60cef868c8e5c04025b08d78222cdeed819093a6bd5117b30d98b3bc69989be2f84e0043761b2686c2060db81c4cc1a3`),
            Context:     fromHex(`c499e583a24617d0b741677665b75ab65bf95ea9971802d7e73d476b8267bce40697b89efa7d9efbf1a3fcd404f2e58f539df3326ae69adedf17f8fb`),
            L:           0x200,
            K0:          fromHex(`13604558349b96745683036e8232ec5c78b923854d3b3d0e144befe773a406d1183b62cdaa05f7e560769fd286137a80b23faad6309f90bfcbd83f05c4f788a3`),
        },
        {
            NewCipher:   seed.NewCipher,
            CounterSize: 32,
            KI:          fromHex(`d4b33a390b92de3bca3c806c19c44b36`),
            Label:       fromHex(`aec9e38d96c1e2586f5054860cc0f6f2e98b76ff9fe481f5595eb76cecd3c58a9560469a31b10dd97f57bf178350b7f8ba60d5e3483056c0cec5a8a3`),
            Context:     fromHex(`3afb990af85f083ff6af9409066101a99bc78754245cf47918d4d2f2469a6cbf2a6700e4146a4e2af1bde78706a73287a547c4982d2d0ffc39b5078d`),
            L:           0x200,
            K0:          fromHex(`d70b91dd72af55bd22e7fc5029b9d6e8b68649b47c429bd1a49d893d41dea67f36271eab939aa6b5b2cf265a01d50f26bfb5ee26d17ce4c6470a055bc2e0b85c`),
        },
        {
            NewCipher:   seed.NewCipher,
            CounterSize: 0,
            KI:          fromHex(`f666f6c71e65669e464060abc58f86cc`),
            Label:       fromHex(`c3c4b1a34a5c3263cea91e3ae6e609f9e66d04a21f6fdda23ce8de919ba82008939f12c5b7d50ae29d4e7158226d630a8d43914d693d7a4504483001`),
            Context:     fromHex(`3755274de4602482fc9775b1cbd693005a5d268e55756828ff3836833de0a056d2d9873bb5f7785f1f6d80e9d4fd409d0052b37ec235fde262d1d4df`),
            L:           0x200,
            K0:          fromHex(`821b8985dab6022e8cb4b881ec82311eb333d50fe97c8ffe07f2fb48ba50ad335c7ba7315d223572205f1ec21183576307d93d71593268658d3b816a0692dfb7`),
        },
    }
)

// ===========

func Test_HMAC_CounterModeKey(t *testing.T) {
    var got []byte
    for idx, tc := range testcasesHMACCtr {
        want := tc.K0
        got = CounterModeKey(NewHMACPRF(tc.Hash), tc.KI, tc.Label, tc.Context, tc.CounterSize, tc.L/8)

        if !bytes.Equal(got, want) {
            t.Errorf("failed test case %d, got %x, want %x", idx, got, want)
        }
    }
}

func Test_HMAC_FeedbackModeKey(t *testing.T) {
    var got []byte
    for idx, tc := range testcasesHMACFB {
        want := tc.K0
        got = FeedbackModeKey(NewHMACPRF(tc.Hash), tc.KI, tc.Label, tc.Context, tc.IV, tc.CounterSize, tc.L/8)

        if !bytes.Equal(got, want) {
            t.Errorf("failed test case %d, got %x, want %x", idx, got, want)
        }
    }
}

func Test_HMAC_DoublePipeModeKey(t *testing.T) {
    var got []byte
    for idx, tc := range testcasesHMACDP {
        want := tc.K0
        got = PipelineModeKey(NewHMACPRF(tc.Hash), tc.KI, tc.Label, tc.Context, tc.CounterSize, tc.L/8)

        if !bytes.Equal(got, want) {
            t.Errorf("failed test case %d, got %x, want %x", idx, got, want)
        }
    }
}

/**
TTAK.KO-12.0333-Part2

HMAC-based Key Derivation Functions
- Part2: Hash Function SHA-2
*/

type testVectorHMAC struct {
    Hash        func() hash.Hash
    KI, Label   []byte
    Context, IV []byte
    L           int // bits
    CounterSize int
    K0          []byte
}

var (
    testcasesHMACCtr = []testVectorHMAC{
        {
            // 5.1 HMAC-SHA-224
            Hash:        sha256.New224,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x0230,
            CounterSize: 1,
            K0:          fromHex(`e50dccef026d0d446f34c90f919bbff924cb57e09caa9ec30f05eaba00619c4998eb35f28295dac8ef49efd6865c7e5f847d62daee89339dfc04d77a29a3edf406ffe053219d`),
        },
        {
            // 5.2 HMAC-SHA-256
            Hash:        sha256.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x0280,
            CounterSize: 1,
            K0:          fromHex(`8da6974e8e8683042d73b24239658e7e2cef712e9335059cd34d5b2f8a25e9c94a6e8b64bddc77688aad7390ce08e9107bf1d165edf0c41dad8e9195549da3b2ef33b2af0c803c6d36c392f745753ab9`),
        },
        {
            // 5.3 HMAC-SHA-384
            Hash:        sha512.New384,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x03C0,
            CounterSize: 1,
            K0:          fromHex(`aa66fcf02050a4a0ae12eb9a7be4263374fcd08127634e05d6afe4237d10a6e75042ab595d9b08d72bcbd11d5cf727e9420f220a19aad1e5aaf156aebf70e6dfdd0d9f350548cbc175e29c533138f99272ad7767952258d0d30b2d749d41cafd0234aaa094dd2189c49f6568b4c001dd52d8ad6b63c724f8`),
        },
        {
            // 5.4 HMAC-SHA-512의 단계별 참조구현값
            Hash:        sha512.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x0500,
            CounterSize: 1,
            K0:          fromHex(`19bd6999e03d0250ee5ae90a78429897fcaf7498c6a2fc44245ee4bd9455b19e343ab44e98d97d8a75460126647579a1c8b4d9ce796f38688acb1d03613f7dd359a3df3109ce3dc95df83cba0e13d991ea48abd145025e942f1cf78dad4b62a9f7aa0b532c64b5ddc233dd6db910c83664cb373b6ba3dbd5d4751c5284c9aa2f73aa82e6233b6a8a51b08441127e838700e4480ee8b5300cbad5fe48ba2a4ab1`),
        },
    }

    testcasesHMACFB = []testVectorHMAC{
        // 6.1 HMAC-SHA-224
        {
            // 6.1.1
            Hash:        sha256.New224,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x0230,
            CounterSize: 1,
            K0:          fromHex(`fc211d4bbb65e20544617963fdab1f5217837ec583d45b4fb45208ffd56179c61dc5b54e04dbab27481706941cafe4565f89d40f16a6ce96d2d2f9d71b3aad54135b04c69c5e`),
        },
        {
            // 6.1.2
            Hash:        sha256.New224,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          nil,
            L:           0x0230,
            CounterSize: 1,
            K0:          fromHex(`e50dccef026d0d446f34c90f919bbff924cb57e09caa9ec30f05eaba66227939ddbc98fb6b066429c0b694399a21f42bad3445917ec5068b87b6f6c97145d096958594fb4bd4`),
        },
        {
            // 6.1.3
            Hash:        sha256.New224,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x0230,
            CounterSize: 0,
            K0:          fromHex(`08d1602aef799313203f31dee8296a72ada6da376a6433bc05981b40e80e72f8923290b616bc30fd96c3af7f133bbc9660bafbec2bcc656d2efaefb8c7b4da4d79d4d9f85c72`),
        },
        {
            // 6.1.4
            Hash:        sha256.New224,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x0230,
            CounterSize: 0,
            K0:          fromHex(`08d1602aef799313203f31dee8296a72ada6da376a6433bc05981b40e80e72f8923290b616bc30fd96c3af7f133bbc9660bafbec2bcc656d2efaefb8c7b4da4d79d4d9f85c72`),
        },
        // 6.2 HMAC-SHA-256
        {
            // 6.2.1
            Hash:        sha256.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            L:           0x0280,
            CounterSize: 1,
            K0:          fromHex(`c976ededeabac660620a1bfb10f8f1471c445600d4b639de34cff39d7796f0a4147eb3426930257c2dd9990bdf95441f49f78bc03c6e63a2c306c32b46fac3afbae4ccf905d7fcc6127167fa77506709`),
        },
        {
            // 6.2.2
            Hash:        sha256.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          nil,
            L:           0x0280,
            CounterSize: 1,
            K0:          fromHex(`8da6974e8e8683042d73b24239658e7e2cef712e9335059cd34d5b2f8a25e9c90e905156c6141095efe48d6d797c51a5fe3a51202a99390697294d3f784c8388e3da32cb27d3ac2b32eaca99b971c2f0`),
        },
        {
            // 6.2.3
            Hash:        sha256.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            L:           0x0280,
            CounterSize: 0,
            K0:          fromHex(`0dec972f54944b77c2bc3d54ba89e2d513c4a1226a738631f14fec1f919ed7f12e98d548a0e293238a7dc423d3bc8f92bc5253b59904709732817730939e6e1225ca8a6c45ee39c2b65a146d7bc8d36a`),
        },
        {
            // 6.2.4
            Hash:        sha256.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          nil,
            L:           0x0280,
            CounterSize: 0,
            K0:          fromHex(`8005439e7f5d28f81d1fe0f640b5d6dfafa8e9266bcc248ad6197280c8a65f1bd22a07b187c697ff56190d7bf61ea5c6d2217abd3a114a643d6ffe9259c50db2fcb17fb72b29463293a580f394ca3c9d`),
        },
        // 6.3 HMAC-SHA-384
        {
            // 6.3.1
            Hash:        sha512.New384,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            L:           0x03C0,
            CounterSize: 1,
            K0:          fromHex(`69ae00a7556ecec8769493b4937a473e25a322a0f9e9a68326ddb0ce512c5cf0b4dd7823ede1d4ee45cdee7bc5e5a34769aee0fb17194af45d2edfd6b9f6e87f3f13419efe31a965c20284b5c956b4a0ac14f24b479d589556f5e10a3dfd6fa8bd2d93fcdc02585eafc055f3db4446873add76fc465cf4ea`),
        },
        {
            // 6.3.2
            Hash:        sha512.New384,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          nil,
            L:           0x03C0,
            CounterSize: 1,
            K0:          fromHex(`aa66fcf02050a4a0ae12eb9a7be4263374fcd08127634e05d6afe4237d10a6e75042ab595d9b08d72bcbd11d5cf727e9b70d5096bd3fa298448355184bea1198b8213bd9a8fb485910209cd630115e4bd87c16898ee0d0b5f20da76fe1d82bf9e05118a3f8d5a1dc74ebbeaf401aac96394ccfdd425a2eeb`),
        },
        {
            // 6.3.3
            Hash:        sha512.New384,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            L:           0x03C0,
            CounterSize: 0,
            K0:          fromHex(`612ca163396ec96b6ae094eaed548e1f649adce06300ab252705f65124ca63e9eac39e5bbb3e440f62a5d2595cccebed80ebd68a337581817a4e1bd0c320ffe36ab83c29a415660e0e859fcf3e4c6eb2107425a179263dcdd79cb97dbb810afa3b09a0cd2e1045f88666581da70294b0fc69032cd4c98fb3`),
        },
        {
            // 6.3.4
            Hash:        sha512.New384,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          nil,
            L:           0x03C0,
            CounterSize: 0,
            K0:          fromHex(`4011a8396cf4caa2aedc8e7ad400641e94af29cc98d6be574203db5b1276dab20cccedca5a6f4678eeefdf5effe0d05ff622a6303e4eeea0fc3e9c6dc3349fc7ecbaab0de9b069e3448f80d49f9cd0d707ccd6fa5a8acdb84b4a5b47f5adf387698c3ac63e07d18c589a880093c4bd28355a7a656b2f6493`),
        },
        // 6.4 HMAC-SHA-512
        {
            // 6.4.1
            Hash:        sha512.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            L:           0x0500,
            CounterSize: 1,
            K0:          fromHex(`833fa5ecd02726858d6486bf3a93429b0d2f3882d791b26434121e7de50a66414707625fcd0067390f4ead1ab4e511d62f479aaef7aa22e3876ed3ee9866e7405b6cf435bbd313dbea90752d495859f40209e38dac39bfa2d9bdd28a70db4db0829304d75c7c62c792e87a728832a91eb67d0b5d56e3c7a972a6cb5388610899306c36630ee1a80c886e45eb8131884b0c02b914b8ab847917b8407b8d029408`),
        },
        {
            // 6.4.2
            Hash:        sha512.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          nil,
            L:           0x0500,
            CounterSize: 1,
            K0:          fromHex(`19bd6999e03d0250ee5ae90a78429897fcaf7498c6a2fc44245ee4bd9455b19e343ab44e98d97d8a75460126647579a1c8b4d9ce796f38688acb1d03613f7dd3a91e9a8953e9593a2ea6d8a6311e0e80bcf3d6dd81fc1b9230e657464df9997d032a76725d868b6ded739a70e273e5c29fe922a03200371d3e587c2dcfd7a02083746b74c09591995ed75e917ebd77532e5d0da75416a668d76ee6b877d05bc5`),
        },
        {
            // 6.4.3
            Hash:        sha512.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            L:           0x0500,
            CounterSize: 0,
            K0:          fromHex(`2ddd5c4ae498189e38318472306347206e4ef9cb5447c605a0104b054922b13d2e2e8b98a10eed328a208b3e4bc27a68f397d5a28e8d10d8b7c1f402c90f250489179d8617a963b6e4f1499888beb7d794535c2366376f7ecd86e7d779528aefca7f926befd98e5d1951af5a157c25f7c9d3a0c08bbb85ac30995732dd13ae4ab9fd332c98a7908ccffec6e9574b45a5284bff4f68a96618c4fa88e95c29e39d`),
        },
        {
            // 6.4.4
            Hash:        sha512.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            IV:          nil,
            L:           0x0500,
            CounterSize: 0,
            K0:          fromHex(`b78b6c62a332158347e6afb027d1d74ff47a35b5e75aa0a52f5bce12aedc372091063e61e4fa73c05db78211b572fc7821abc8e473dc1cbed34471ec32a4ee9cad519e1bcb7dad930fe966ac6e3a0d410afeadcf0ee812639043027db76723e9d7a2695653c61283fe33bafbbec85d9263d50c6911e1a16932c0d65afbbc6001e760fd3c41090f06aa2259924f5da09a16f6bb9cfd86e2c27d406b1a64c233c2`),
        },
    }

    testcasesHMACDP = []testVectorHMAC{
        // 7.1 HMAC-SHA-224
        {
            // 7.1.1
            Hash:        sha256.New224,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x0230,
            CounterSize: 1,
            K0:          fromHex(`91e89383285b9691d38d0f0833cac5a030cc6a51741753e26b5f042f2687b69e972feaeaf6d4732353fd6095e56e0aa338ad361c24df78b37f6503437debf14ceda8efa84c9a`),
        },
        {
            // 7.1.2
            Hash:        sha256.New224,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x0230,
            CounterSize: 0,
            K0:          fromHex(`6e6f3681408fa8a8c0271b451d460487e645ee1cc3882c514b7e2c92fede6faf07ccf39fba75fc19f5a5b6035b6bd49bebc8fb5caf39e4c37df1788b63485a1956d5c395c14e`),
        },
        // 7.2 HMAC-SHA-256
        {
            // 7.1.1
            Hash:        sha256.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x0280,
            CounterSize: 1,
            K0:          fromHex(`87fbdd5fa8238f98deee8715a6987b33db68ee2807b289a0f42fe99350784f9c7899174abc221c4d2dcd21d850332223ca01b827324ae506c8ef58fa165a23534f998ed2dfea25a935f964e14831cabc`),
        },
        {
            // 7.1.2
            Hash:        sha256.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x0280,
            CounterSize: 0,
            K0:          fromHex(`d22a07b187c697ff56190d7bf61ea5c6d2217abd3a114a643d6ffe9259c50db2a62327c9f79a5b723b3ed727aadc58470fa473d3171d02ecd2c8017b4ba48fd6edfcc08ca9a3197aad5f19591f0c4812`),
        },
        // 7.3 HMAC-SHA-384
        {
            // 7.3.1
            Hash:        sha512.New384,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x03C0,
            CounterSize: 1,
            K0:          fromHex(`d4cf1159dbf331b40985a160531d73f2166303ca0bb46ad717e9207cd36a29f42eb748490e94e07596ae3a1f099f928a78e27a472f7d9bd0965220846f2367af5c8e16c9d680841a5b02e5fcbf65d70dc82cfd3c6d7589536a24ac5342529359c13536d6b440a652d0c62d13a3411f26495dfc680ac55fd4`),
        },
        {
            // 7.3.2
            Hash:        sha512.New384,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x03C0,
            CounterSize: 0,
            K0:          fromHex(`f622a6303e4eeea0fc3e9c6dc3349fc7ecbaab0de9b069e3448f80d49f9cd0d707ccd6fa5a8acdb84b4a5b47f5adf387a048db4855c63f8a8d6a1b5d7c4c730535cbc6a647f291cc0c66870c1e01cc7a3cac9b07553da694b54ab2363d7972fdbf7ce73488ebf9045d5e978ceb1490e433f82dbe915fe223`),
        },
        // 7.4 HMAC-SHA-512
        {
            // 7.3.1
            Hash:        sha512.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x0500,
            CounterSize: 1,
            K0:          fromHex(`d3a6779fd531ff6f327ec70f26d1f54798c867e86eae28ae6ced773ba2382190a8c72fb5c912c9f8a7f4a9cdf65928d133e28b71764c841959d7a1133c08fd65df7ab5c457be9ce477ba71d3b54eb5c4cd824216e5f3267f300c071045cd368937f0e730328b364a6ae0a8e9a80ddac6430dc02247408e3b97a6a063502be9b0f52e2742021aab1f651b7063b25876310c0027bcf36ea9b4d577d9fc51f88b64`),
        },
        {
            // 7.3.2
            Hash:        sha512.New,
            KI:          fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`),
            Label:       fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            Context:     fromHex(`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb`),
            L:           0x0500,
            CounterSize: 0,
            K0:          fromHex(`ad519e1bcb7dad930fe966ac6e3a0d410afeadcf0ee812639043027db76723e9d7a2695653c61283fe33bafbbec85d9263d50c6911e1a16932c0d65afbbc60017dbd12e3ff6b1aa617894cca40b5d3d168daed59d4c41a2464cbfc2d3b9408a171b5e7e14128ffdd9f9f4cc760907e8ed7a8cfdd3515f7d90ce5cb2c57e0fe19eaeb52a4ebb7a4ab25ac273dfb078f413dda8f65f81b8c7fb9aaebad8e36cc3d`),
        },
    }
)
