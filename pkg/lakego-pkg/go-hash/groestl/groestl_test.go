package groestl

import (
    "bytes"
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_Hash224(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New224()
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }
}

func Test_Hash256(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New256()
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }
}

func Test_Hash384(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New384()
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }
}

func Test_Hash512(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New512()
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }
}

type testData struct {
    msg []byte
    md []byte
}

// 28 bytes
func Test_Hash224_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex("CC"),
           fromHex("62E367662ADF9317154F877FD740C23FC2356080B477DAC847BE2EB2"),
        },
        {
           fromHex("1F877C"),
           fromHex("1DC3EF787D0D92A2E7B66E28A5BBC14A0F533E3946F3EEECEDC001F9"),
        },
        {
           fromHex("2FDA311DBBA27321C5329510FAE6948F03210B76D43E7448D1689A063877B6D14C4F6D0EAA96C150051371F7DD8A4119F7DA5C483CC3E6723C01FB7D"),
           fromHex("456D3A058E360BE744C96A2FE2767D73B6FB7A7B670DD20C57009370"),
        },
        {
           fromHex("D782ABB72A5BE3392757BE02D3E45BE6E2099D6F000D042C8A543F50ED6EBC055A7F133B0DD8E9BC348536EDCAAE2E12EC18E8837DF7A1B3C87EC46D50C241DEE820FD586197552DC20BEEA50F445A07A38F1768A39E2B2FF05DDDEDF751F1DEF612D2E4D810DAA3A0CC904516F9A43AF660315385178A529E51F8AAE141808C8BC5D7B60CAC26BB984AC1890D0436EF780426C547E94A7B08F01ACBFC4A3825EAE04F520A9016F2FB8BF5165ED12736FC71E36A49A73614739EAA3EC834069B1B40F1350C2B3AB885C02C640B9F7686ED5F99527E41CFCD796FE4C256C9173186C226169FF257954EBDA81C0E5F99"),
           fromHex("46BE8BF83840FD417A10E2F9495A151E14CC1CC9F4408524F1F6CE20"),
        },
        {
           fromHex("83167FF53704C3AA19E9FB3303539759C46DD4091A52DDAE9AD86408B69335989E61414BC20AB4D01220E35241EFF5C9522B079FBA597674C8D716FE441E566110B6211531CECCF8FD06BC8E511D00785E57788ED9A1C5C73524F01830D2E1148C92D0EDC97113E3B7B5CD3049627ABDB8B39DD4D6890E0EE91993F92B03354A88F52251C546E64434D9C3D74544F23FB93E5A2D2F1FB15545B4E1367C97335B0291944C8B730AD3D4789273FA44FB98D78A36C3C3764ABEEAC7C569C1E43A352E5B770C3504F87090DEE075A1C4C85C0C39CF421BDCC615F9EFF6CB4FE6468004AECE5F30E1ECC6DB22AD9939BB2B0CCC96521DFBF4AE008B5B46BC006E"),
           fromHex("B39F9020CADEA480767ED35DEB71ECF77C1D701CDB5E05E2C4424582"),
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

        sum2 := Sum224(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum224 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash256_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex("1F877C"),
           fromHex("05FE7DE2D8CE1770DF766739F788037D0CF2CA7C2B7620835CC34F45B3FCF919"),
        },
        {
           fromHex("C71BD7941F41DF044A2927A8FF55B4B467C33D089F0988AA253D294ADDBDB32530C0D4208B10D9959823F0C0F0734684006DF79F7099870F6BF53211A88D"),
           fromHex("74621CA404EE51690DC5AB30CCB6219FB458BF35F534068AAC14C357C49A3CD7"),
        },
        {
           fromHex("A7ED84749CCC56BB1DFBA57119D279D412B8A986886D810F067AF349E8749E9EA746A60B03742636C464FC1EE233ACC52C1983914692B64309EDFDF29F1AB912EC3E8DA074D3F1D231511F5756F0B6EEAD3E89A6A88FE330A10FACE267BFFBFC3E3090C7FD9A850561F363AD75EA881E7244F80FF55802D5EF7A1A4E7B89FCFA80F16DF54D1B056EE637E6964B9E0FFD15B6196BDD7DB270C56B47251485348E49813B4EB9ED122A01B3EA45AD5E1A929DF61D5C0F3E77E1FDC356B63883A60E9CBB9FC3E00C2F32DBD469659883F690C6772E335F617BC33F161D6F6984252EE12E62B6000AC5231E0C9BC65BE223D8DFD94C5004A101AF9FD6C0FB"),
           fromHex("ECCD55E2A00B3917B219E66D5FC9BD5A1A581ABF105863FA8285CA0E6F09F5A0"),
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

        sum2 := Sum256(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum256 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash384_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex("C6F50BB74E29"),
           fromHex("3E3197BA9ECA972F90EA2C04FF35B8410D96A949EBE4847FFF070497A20281B4AAB2BBE23DF5381CB1BBA90BD67C627C"),
        },
        {
           fromHex("4B127FDE5DE733A1680C2790363627E63AC8A3F1B4707D982CAEA258655D9BF18F89AFE54127482BA01E08845594B671306A025C9A5C5B6F93B0A39522DC877437BE5C2436CBF300CE7AB6747934FCFC30AEAAF6"),
           fromHex("51FB0A99436C992827E75AA741C03703D568FC6D6BE7C6DAA28E9CB60D76F871B6DE47361AB778419D8ABA7EF18126CF"),
        },
        {
           fromHex("A7ED84749CCC56BB1DFBA57119D279D412B8A986886D810F067AF349E8749E9EA746A60B03742636C464FC1EE233ACC52C1983914692B64309EDFDF29F1AB912EC3E8DA074D3F1D231511F5756F0B6EEAD3E89A6A88FE330A10FACE267BFFBFC3E3090C7FD9A850561F363AD75EA881E7244F80FF55802D5EF7A1A4E7B89FCFA80F16DF54D1B056EE637E6964B9E0FFD15B6196BDD7DB270C56B47251485348E49813B4EB9ED122A01B3EA45AD5E1A929DF61D5C0F3E77E1FDC356B63883A60E9CBB9FC3E00C2F32DBD469659883F690C6772E335F617BC33F161D6F6984252EE12E62B6000AC5231E0C9BC65BE223D8DFD94C5004A101AF9FD6C0FB"),
           fromHex("88EE746F15425F266DDC7639E9F2EF72E9A1A1ACF2732565CE0BAD97BB2C5C95210A0583D0C998003389C525526BB566"),
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

        sum2 := Sum384(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum384 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash512_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex("C1ECFDFC"),
           fromHex("4726D760203C1EAF847F6837C74C16ADCEF5B55EAD5768A7C13E21A33D0D7B740F52DE8C81356DA63DABA791DA6680AF015DEB81246550201F232822BB087CE5"),
        },
        {
           fromHex("F690A132AB46B28EDFA6479283D6444E371C6459108AFD9C35DBD235E0B6B6FF4C4EA58E7554BD002460433B2164CA51E868F7947D7D7A0D792E4ABF0BE5F450853CC40D85485B2B8857EA31B5EA6E4CCFA2F3A7EF3380066D7D8979FDAC618AAD3D7E886DEA4F005AE4AD05E5065F"),
           fromHex("814A596249AC113CF394A5E348DF55293BCE8401BF9F0EC34114BB55EA1A047283AF655D45AC45717C60F66398A36CD1F7F354AE6FD327D6F50F1C978C704433"),
        },
        {
           fromHex("83167FF53704C3AA19E9FB3303539759C46DD4091A52DDAE9AD86408B69335989E61414BC20AB4D01220E35241EFF5C9522B079FBA597674C8D716FE441E566110B6211531CECCF8FD06BC8E511D00785E57788ED9A1C5C73524F01830D2E1148C92D0EDC97113E3B7B5CD3049627ABDB8B39DD4D6890E0EE91993F92B03354A88F52251C546E64434D9C3D74544F23FB93E5A2D2F1FB15545B4E1367C97335B0291944C8B730AD3D4789273FA44FB98D78A36C3C3764ABEEAC7C569C1E43A352E5B770C3504F87090DEE075A1C4C85C0C39CF421BDCC615F9EFF6CB4FE6468004AECE5F30E1ECC6DB22AD9939BB2B0CCC96521DFBF4AE008B5B46BC006E"),
           fromHex("54E3A7AE5D39ED0314A999177C32C7FE4FDA34DE35E034E0A52A62D900A638C64AA68E317A9880584E34B62D3A9A49185CBAEF75D8EAED748497D6DAD28F3986"),
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

        sum2 := Sum512(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum512 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}
