package haval

import (
    "bytes"
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func fromString(s string) []byte {
    return []byte(s)
}

type testData struct {
    msg []byte
    md []byte
}

func Test_Hash128_3_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("C68F39913F901F3DDF44C707357A7D70"),
        },
        {
           fromString("a"),
           fromHex("0CD40739683E15F01CA5DBCEEF4059F1"),
        },
        {
           fromString("HAVAL"),
           fromHex("DC1F3C893D17CC4EDD9AE94AF76A0AF0"),
        },
        {
           fromString("0123456789"),
           fromHex("D4BE2164EF387D9F4D46EA8EFB180CF5"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("DC502247FB3EB8376109EDA32D361D82"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("DE5EB3F7D9EB08FAE7A07D68E3047EC6"),
        },
    }

    h := New128_3()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New128_3 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum128_3(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum128_3 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash160_3_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("D353C3AE22A25401D257643836D7231A9A95F953"),
        },
        {
           fromString("a"),
           fromHex("4DA08F514A7275DBC4CECE4A347385983983A830"),
        },
        {
           fromString("HAVAL"),
           fromHex("8822BC6F3E694E73798920C77CE3245120DD8214"),
        },
        {
           fromString("0123456789"),
           fromHex("BE68981EB3EBD3F6748B081EE5D4E1818F9BA86C"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("EBA9FA6050F24C07C29D1834A60900EA4E32E61B"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("97DC988D97CAAE757BE7523C4E8D4EA63007A4B9"),
        },
    }

    h := New160_3()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New160_3 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum160_3(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum160_3 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash192_3_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("E9C48D7903EAF2A91C5B350151EFCB175C0FC82DE2289A4E"),
        },
        {
           fromString("a"),
           fromHex("B359C8835647F5697472431C142731FF6E2CDDCACC4F6E08"),
        },
        {
           fromString("HAVAL"),
           fromHex("8DA26DDAB4317B392B22B638998FE65B0FBE4610D345CF89"),
        },
        {
           fromString("0123456789"),
           fromHex("DE561F6D818A760D65BDD2823ABE79CDD97E6CFA4021B0C8"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("A25E1456E6863E7D7C74017BB3E098E086AD4BE0580D7056"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("DEF6653091E3005B43A61681014A066CD189009D00856EE7"),
        },
    }

    h := New192_3()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New192_3 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum192_3(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum192_3 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash224_3_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("C5AAE9D47BFFCAAF84A8C6E7CCACD60A0DD1932BE7B1A192B9214B6D"),
        },
        {
           fromString("a"),
           fromHex("731814BA5605C59B673E4CAAE4AD28EEB515B3ABC2B198336794E17B"),
        },
        {
           fromString("HAVAL"),
           fromHex("AD33E0596C575D7175E9F72361CA767C89E46E2609D88E719EE69AAA"),
        },
        {
           fromString("0123456789"),
           fromHex("EE345C97A58190BF0F38BF7CE890231AA5FCF9862BF8E7BEBBF76789"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("06AE38EBC43DB58BD6B1D477C7B4E01B85A1E7B19B0BD088E33B58D1"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("939F7ED7801C1CE4B32BC74A4056EEE6081C999ED246907ADBA880A7"),
        },
    }

    h := New224_3()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New224_3 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum224_3(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum224_3 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash256_3_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("4F6938531F0BC8991F62DA7BBD6F7DE3FAD44562B8C6F4EBF146D5B4E46F7C17"),
        },
        {
           fromString("a"),
           fromHex("47C838FBB4081D9525A0FF9B1E2C05A98F625714E72DB289010374E27DB021D8"),
        },
        {
           fromString("HAVAL"),
           fromHex("91850C6487C9829E791FC5B58E98E372F3063256BB7D313A93F1F83B426AEDCC"),
        },
        {
           fromString("0123456789"),
           fromHex("63238D99C02BE18C3C5DB7CCE8432F51329012C228CCC17EF048A5D0FD22D4AE"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("72FAD4BDE1DA8C8332FB60561A780E7F504F21547B98686824FC33FC796AFA76"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("899397D96489281E9E76D5E65ABAB751F312E06C06C07C9C1D42ABD31BB6A404"),
        },
    }

    h := New256_3()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New256_3 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum256_3(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum256_3 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

// ========

func Test_Hash128_4_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("EE6BBF4D6A46A679B3A856C88538BB98"),
        },
        {
           fromString("a"),
           fromHex("5CD07F03330C3B5020B29BA75911E17D"),
        },
        {
           fromString("HAVAL"),
           fromHex("958195D3DAC591030EAA0292A37A0CF2"),
        },
        {
           fromString("0123456789"),
           fromHex("2215D3702A80025C858062C53D76CBE5"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("B2A73B99775FFB17CD8781B85EC66221"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("CAD57C0563BDA208D66BB89EB922E2A2"),
        },
    }

    h := New128_4()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New128_4 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum128_4(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum128_4 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash160_4_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("1D33AAE1BE4146DBAACA0B6E70D7A11F10801525"),
        },
        {
           fromString("a"),
           fromHex("E0A5BE29627332034D4DD8A910A1A0E6FE04084D"),
        },
        {
           fromString("HAVAL"),
           fromHex("221BA4DD206172F12C2EBA3295FDE08D25B2F982"),
        },
        {
           fromString("0123456789"),
           fromHex("E387C743D14DF304CE5C7A552F4C19CA9B8E741C"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("1C7884AF86D11AC120FE5DF75CEE792D2DFA48EF"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("148334AAD24B658BDC946C521CDD2B1256608C7B"),
        },
    }

    h := New160_4()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New160_4 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum160_4(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum160_4 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash192_4_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("4A8372945AFA55C7DEAD800311272523CA19D42EA47B72DA"),
        },
        {
           fromString("a"),
           fromHex("856C19F86214EA9A8A2F0C4B758B973CCE72A2D8FF55505C"),
        },
        {
           fromString("HAVAL"),
           fromHex("0C1396D7772689C46773F3DAACA4EFA982ADBFB2F1467EEA"),
        },
        {
           fromString("0123456789"),
           fromHex("C3A5420BB9D7D82A168F6624E954AAA9CDC69FB0F67D785E"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("2E2E581D725E799FDA1948C75E85A28CFE1CF0C6324A1ADA"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("E5C9F81AE0B31FC8780FC37CB63BB4EC96496F79A9B58344"),
        },
    }

    h := New192_4()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New192_4 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum192_4(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum192_4 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash224_4_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("3E56243275B3B81561750550E36FCD676AD2F5DD9E15F2E89E6ED78E"),
        },
        {
           fromString("a"),
           fromHex("742F1DBEEAF17F74960558B44F08AA98BDC7D967E6C0AB8F799B3AC1"),
        },
        {
           fromString("HAVAL"),
           fromHex("85538FFC06F3B1C693C792C49175639666F1DDE227DA8BD000C1E6B4"),
        },
        {
           fromString("0123456789"),
           fromHex("BEBD7816F09BAEECF8903B1B9BC672D9FA428E462BA699F814841529"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("A0AC696CDB2030FA67F6CC1D14613B1962A7B69B4378A9A1B9738796"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("3E63C95727E0CD85D42034191314401E42AB9063A94772647E3E8E0F"),
        },
    }

    h := New224_4()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New224_4 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum224_4(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum224_4 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash256_4_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("C92B2E23091E80E375DADCE26982482D197B1A2521BE82DA819F8CA2C579B99B"),
        },
        {
           fromString("a"),
           fromHex("E686D2394A49B44D306ECE295CF9021553221DB132B36CC0FF5B593D39295899"),
        },
        {
           fromString("HAVAL"),
           fromHex("E20643CFA66F5BE2145D13ED09C2FF622B3F0DA426A693FA3B3E529CA89E0D3C"),
        },
        {
           fromString("0123456789"),
           fromHex("ACE5D6E5B155F7C9159F6280327B07CBD4FF54143DC333F0582E9BCEB895C05D"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("124F6EB645DC407637F8F719CC31250089C89903BF1DB8FAC21EA4614DF4E99A"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("46A3A1DFE867EDE652425CCD7FE8006537EAD26372251686BEA286DA152DC35A"),
        },
    }

    h := New256_4()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New256_4 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum256_4(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum256_4 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

// ========

func Test_Hash128_5_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("184B8482A0C050DCA54B59C7F05BF5DD"),
        },
        {
           fromString("a"),
           fromHex("F23FBE704BE8494BFA7A7FB4F8AB09E5"),
        },
        {
           fromString("HAVAL"),
           fromHex("C97990F4FCC8FBA76AF935C405995355"),
        },
        {
           fromString("0123456789"),
           fromHex("466FDCD81C3477CAC6A31FFA1C999CA8"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("0EFFF71D7D14344CBA1F4B25F924A693"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("4B27D04DDB516BDCDFEB96EB8C7C8E90"),
        },
    }

    h := New128_5()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New128_5 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum128_5(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum128_5 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash160_5_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("255158CFC1EED1A7BE7C55DDD64D9790415B933B"),
        },
        {
           fromString("a"),
           fromHex("F5147DF7ABC5E3C81B031268927C2B5761B5A2B5"),
        },
        {
           fromString("HAVAL"),
           fromHex("7730CA184CEA2272E88571A7D533E035F33B1096"),
        },
        {
           fromString("0123456789"),
           fromHex("41CC7C1267E88CEF0BB93697D0B6C8AFE59061E6"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("917836A9D27EED42D406F6002E7D11A0F87C404C"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("6DDBDE98EA1C4F8C7F360FB9163C7C952680AA70"),
        },
    }

    h := New160_5()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New160_5 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum160_5(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum160_5 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash192_5_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("4839D0626F95935E17EE2FC4509387BBE2CC46CB382FFE85"),
        },
        {
           fromString("a"),
           fromHex("5FFA3B3548A6E2CFC06B7908CEB5263595DF67CF9C4B9341"),
        },
        {
           fromString("HAVAL"),
           fromHex("794A896D1780B76E2767CC4011BAD8885D5CE6BD835A71B8"),
        },
        {
           fromString("0123456789"),
           fromHex("A0B635746E6CFFFFD4B4A503620FEF1040C6C0C5C326476E"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("85F1F1C0ECA04330CF2DE5C8C83CF85A611B696F793284DE"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("D651C8AC45C9050810D9FD64FC919909900C4664BE0336D0"),
        },
    }

    h := New192_5()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New192_5 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum192_5(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum192_5 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash224_5_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("4A0513C032754F5582A758D35917AC9ADF3854219B39E3AC77D1837E"),
        },
        {
           fromString("a"),
           fromHex("67B3CB8D4068E3641FA4F156E03B52978B421947328BFB9168C7655D"),
        },
        {
           fromString("HAVAL"),
           fromHex("9D7AE77B8C5C8C1C0BA854EBE3B2673C4163CFD304AD7CD527CE0C82"),
        },
        {
           fromString("0123456789"),
           fromHex("59836D19269135BC815F37B2AEB15F894B5435F2C698D57716760F2B"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("1B360ACFF7806502B5D40C71D237CC0C40343D2000AE2F65CF487C94"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("180AED7F988266016719F60148BA2C9B4F5EC3B9758960FC735DF274"),
        },
    }

    h := New224_5()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New224_5 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum224_5(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum224_5 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash256_5_Check(t *testing.T) {
   tests := []testData{
        {
           fromString(""),
           fromHex("BE417BB4DD5CFB76C7126F4F8EEB1553A449039307B1A3CD451DBFDC0FBBE330"),
        },
        {
           fromString("a"),
           fromHex("DE8FD5EE72A5E4265AF0A756F4E1A1F65C9B2B2F47CF17ECF0D1B88679A3E22F"),
        },
        {
           fromString("HAVAL"),
           fromHex("153D2C81CD3C24249AB7CD476934287AF845AF37F53F51F5C7E2BE99BA28443F"),
        },
        {
           fromString("0123456789"),
           fromHex("357E2032774ABBF5F04D5F1DEC665112EA03B23E6E00425D0DF75EA155813126"),
        },
        {
           fromString("abcdefghijklmnopqrstuvwxyz"),
           fromHex("C9C7D8AFA159FD9E965CB83FF5EE6F58AEDA352C0EFF005548153A61551C38EE"),
        },
        {
           fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           fromHex("B45CB6E62F2B1320E4F8F1B0B273D45ADD47C321FD23999DCF403AC37636D963"),
        },
    }

    h := New256_5()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New256_5 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum256_5(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum256_5 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

