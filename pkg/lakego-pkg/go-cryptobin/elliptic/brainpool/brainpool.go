package brainpool

import (
    "sync"
    "math/big"
    "encoding/asn1"
    "crypto/elliptic"
)

// link https://datatracker.ietf.org/doc/html/rfc5639

var (
    oidBrainpool = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1}

    OIDBrainpoolP160r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 1}
    OIDBrainpoolP160t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 2}
    OIDBrainpoolP192r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 3}
    OIDBrainpoolP192t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 4}
    OIDBrainpoolP224r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 5}
    OIDBrainpoolP224t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 6}

    OIDBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 7}
    OIDBrainpoolP256t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 8}
    OIDBrainpoolP320r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 9}
    OIDBrainpoolP320t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 10}
    OIDBrainpoolP384r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 11}
    OIDBrainpoolP384t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 12}
    OIDBrainpoolP512r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 13}
    OIDBrainpoolP512t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 14}
)

var (
    once sync.Once

    p160t1, p192t1, p224t1 *elliptic.CurveParams
    p160r1, p192r1, p224r1 *rcurve

    p256t1, p320t1, p384t1, p512t1 *elliptic.CurveParams
    p256r1, p320r1, p384r1, p512r1 *rcurve
)

func bigFromHex(s string) (i *big.Int) {
    i = new(big.Int)
    i.SetString(s, 16)
    return
}

func initAll() {
    initP160t1()
    initP160r1()
    initP192t1()
    initP192r1()
    initP224t1()
    initP224r1()

    initP256t1()
    initP256r1()
    initP320t1()
    initP320r1()
    initP384t1()
    initP384r1()
    initP512t1()
    initP512r1()
}

func initP160t1() {
    p160t1 = &elliptic.CurveParams{Name: "brainpoolP160t1"}
    p160t1.P = bigFromHex("E95E4A5F737059DC60DFC7AD95B3D8139515620F")
    p160t1.N = bigFromHex("E95E4A5F737059DC60DF5991D45029409E60FC09")
    p160t1.B = bigFromHex("7A556B6DAE535B7B51ED2C4D7DAA7A0B5C55F380")
    p160t1.Gx = bigFromHex("B199B13B9B34EFC1397E64BAEB05ACC265FF2378")
    p160t1.Gy = bigFromHex("ADD6718B7C7C1961F0991B842443772152C9E0AD")
    p160t1.BitSize = 160
}

func initP160r1() {
    twisted := p160t1
    params := &elliptic.CurveParams{
        Name:    "brainpoolP160r1",
        P:       twisted.P,
        N:       twisted.N,
        BitSize: twisted.BitSize,
    }
    params.Gx = bigFromHex("BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3")
    params.Gy = bigFromHex("1667CB477A1A8EC338F94741669C976316DA6321")
    z := bigFromHex("24DBFF5DEC9B986BBFE5295A29BFBAE45E0F5D0B")
    p160r1 = newRcurve(twisted, params, z)
}

func initP192t1() {
    p192t1 = &elliptic.CurveParams{Name: "brainpoolP192t1"}
    p192t1.P = bigFromHex("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297")
    p192t1.N = bigFromHex("C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1")
    p192t1.B = bigFromHex("13D56FFAEC78681E68F9DEB43B35BEC2FB68542E27897B79")
    p192t1.Gx = bigFromHex("3AE9E58C82F63C30282E1FE7BBF43FA72C446AF6F4618129")
    p192t1.Gy = bigFromHex("097E2C5667C2223A902AB5CA449D0084B7E5B3DE7CCC01C9")
    p192t1.BitSize = 192
}

func initP192r1() {
    twisted := p192t1
    params := &elliptic.CurveParams{
        Name:    "brainpoolP192r1",
        P:       twisted.P,
        N:       twisted.N,
        BitSize: twisted.BitSize,
    }
    params.Gx = bigFromHex("C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6")
    params.Gy = bigFromHex("14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F")
    z := bigFromHex("1B6F5CC8DB4DC7AF19458A9CB80DC2295E5EB9C3732104CB")
    p192r1 = newRcurve(twisted, params, z)
}

func initP224t1() {
    p224t1 = &elliptic.CurveParams{Name: "brainpoolP224t1"}
    p224t1.P = bigFromHex("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF")
    p224t1.N = bigFromHex("D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F")
    p224t1.B = bigFromHex("4B337D934104CD7BEF271BF60CED1ED20DA14C08B3BB64F18A60888D")
    p224t1.Gx = bigFromHex("6AB1E344CE25FF3896424E7FFE14762ECB49F8928AC0C76029B4D580")
    p224t1.Gy = bigFromHex("0374E9F5143E568CD23F3F4D7C0D4B1E41C8CC0D1C6ABD5F1A46DB4C")
    p224t1.BitSize = 224
}

func initP224r1() {
    twisted := p224t1
    params := &elliptic.CurveParams{
        Name:    "brainpoolP224r1",
        P:       twisted.P,
        N:       twisted.N,
        BitSize: twisted.BitSize,
    }
    params.Gx = bigFromHex("0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D")
    params.Gy = bigFromHex("58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD")
    z := bigFromHex("2DF271E14427A346910CF7A2E6CFA7B3F484E5C2CCE1C8B730E28B3F")
    p224r1 = newRcurve(twisted, params, z)
}

// P160t1 returns a Curve which implements Brainpool P160t1 (see RFC 5639, section 3.4)
func P160t1() elliptic.Curve {
    once.Do(initAll)
    return p160t1
}

// P160r1 returns a Curve which implements Brainpool P160r1 (see RFC 5639, section 3.4)
func P160r1() elliptic.Curve {
    once.Do(initAll)
    return p160r1
}

// P192t1 returns a Curve which implements Brainpool P192t1 (see RFC 5639, section 3.6)
func P192t1() elliptic.Curve {
    once.Do(initAll)
    return p192t1
}

// P192r1 returns a Curve which implements Brainpool P192r1 (see RFC 5639, section 3.6)
func P192r1() elliptic.Curve {
    once.Do(initAll)
    return p192r1
}

// P224t1 returns a Curve which implements Brainpool P224t1 (see RFC 5639, section 3.7)
func P224t1() elliptic.Curve {
    once.Do(initAll)
    return p224t1
}

// P224r1 returns a Curve which implements Brainpool P224r1 (see RFC 5639, section 3.7)
func P224r1() elliptic.Curve {
    once.Do(initAll)
    return p224r1
}

// ========

func initP256t1() {
    p256t1 = &elliptic.CurveParams{Name: "brainpoolP256t1"}
    p256t1.P = bigFromHex("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377")
    p256t1.N = bigFromHex("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7")
    p256t1.B = bigFromHex("662C61C430D84EA4FE66A7733D0B76B7BF93EBC4AF2F49256AE58101FEE92B04")
    p256t1.Gx = bigFromHex("A3E8EB3CC1CFE7B7732213B23A656149AFA142C47AAFBC2B79A191562E1305F4")
    p256t1.Gy = bigFromHex("2D996C823439C56D7F7B22E14644417E69BCB6DE39D027001DABE8F35B25C9BE")
    p256t1.BitSize = 256
}

func initP256r1() {
    twisted := p256t1
    params := &elliptic.CurveParams{
        Name:    "brainpoolP256r1",
        P:       twisted.P,
        N:       twisted.N,
        BitSize: twisted.BitSize,
    }
    params.Gx = bigFromHex("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262")
    params.Gy = bigFromHex("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997")
    z := bigFromHex("3E2D4BD9597B58639AE7AA669CAB9837CF5CF20A2C852D10F655668DFC150EF0")
    p256r1 = newRcurve(twisted, params, z)
}

func initP320t1() {
    p320t1 = &elliptic.CurveParams{Name: "brainpoolP320t1"}
    p320t1.P = bigFromHex("D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27")
    p320t1.N = bigFromHex("D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311")
    p320t1.B = bigFromHex("A7F561E038EB1ED560B3D147DB782013064C19F27ED27C6780AAF77FB8A547CEB5B4FEF422340353")
    p320t1.Gx = bigFromHex("925BE9FB01AFC6FB4D3E7D4990010F813408AB106C4F09CB7EE07868CC136FFF3357F624A21BED52")
    p320t1.Gy = bigFromHex("63BA3A7A27483EBF6671DBEF7ABB30EBEE084E58A0B077AD42A5A0989D1EE71B1B9BC0455FB0D2C3")
    p320t1.BitSize = 320
}

func initP320r1() {
    twisted := p320t1
    params := &elliptic.CurveParams{
        Name:    "brainpoolP320r1",
        P:       twisted.P,
        N:       twisted.N,
        BitSize: twisted.BitSize,
    }
    params.Gx = bigFromHex("43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611")
    params.Gy = bigFromHex("14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1")
    z := bigFromHex("15F75CAF668077F7E85B42EB01F0A81FF56ECD6191D55CB82B7D861458A18FEFC3E5AB7496F3C7B1")
    p320r1 = newRcurve(twisted, params, z)
}

func initP384t1() {
    p384t1 = &elliptic.CurveParams{Name: "brainpoolP384t1"}
    p384t1.P = bigFromHex("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53")
    p384t1.N = bigFromHex("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565")
    p384t1.B = bigFromHex("7F519EADA7BDA81BD826DBA647910F8C4B9346ED8CCDC64E4B1ABD11756DCE1D2074AA263B88805CED70355A33B471EE")
    p384t1.Gx = bigFromHex("18DE98B02DB9A306F2AFCD7235F72A819B80AB12EBD653172476FECD462AABFFC4FF191B946A5F54D8D0AA2F418808CC")
    p384t1.Gy = bigFromHex("25AB056962D30651A114AFD2755AD336747F93475B7A1FCA3B88F2B6A208CCFE469408584DC2B2912675BF5B9E582928")
    p384t1.BitSize = 384
}

func initP384r1() {
    twisted := p384t1
    params := &elliptic.CurveParams{
        Name:    "brainpoolP384r1",
        P:       twisted.P,
        N:       twisted.N,
        BitSize: twisted.BitSize,
    }
    params.Gx = bigFromHex("1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E")
    params.Gy = bigFromHex("8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315")
    z := bigFromHex("41DFE8DD399331F7166A66076734A89CD0D2BCDB7D068E44E1F378F41ECBAE97D2D63DBC87BCCDDCCC5DA39E8589291C")
    p384r1 = newRcurve(twisted, params, z)
}

func initP512t1() {
    p512t1 = &elliptic.CurveParams{Name: "brainpoolP512t1"}
    p512t1.P = bigFromHex("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3")
    p512t1.N = bigFromHex("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069")
    p512t1.B = bigFromHex("7CBBBCF9441CFAB76E1890E46884EAE321F70C0BCB4981527897504BEC3E36A62BCDFA2304976540F6450085F2DAE145C22553B465763689180EA2571867423E")
    p512t1.Gx = bigFromHex("640ECE5C12788717B9C1BA06CBC2A6FEBA85842458C56DDE9DB1758D39C0313D82BA51735CDB3EA499AA77A7D6943A64F7A3F25FE26F06B51BAA2696FA9035DA")
    p512t1.Gy = bigFromHex("5B534BD595F5AF0FA2C892376C84ACE1BB4E3019B71634C01131159CAE03CEE9D9932184BEEF216BD71DF2DADF86A627306ECFF96DBB8BACE198B61E00F8B332")
    p512t1.BitSize = 512
}

func initP512r1() {
    twisted := p512t1
    params := &elliptic.CurveParams{
        Name:    "brainpoolP512r1",
        P:       twisted.P,
        N:       twisted.N,
        BitSize: twisted.BitSize,
    }
    params.Gx = bigFromHex("81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822")
    params.Gy = bigFromHex("7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892")
    z := bigFromHex("12EE58E6764838B69782136F0F2D3BA06E27695716054092E60A80BEDB212B64E585D90BCE13761F85C3F1D2A64E3BE8FEA2220F01EBA5EEB0F35DBD29D922AB")
    p512r1 = newRcurve(twisted, params, z)
}

// P256t1 returns a Curve which implements Brainpool P256t1 (see RFC 5639, section 3.4)
func P256t1() elliptic.Curve {
    once.Do(initAll)
    return p256t1
}

// P256r1 returns a Curve which implements Brainpool P256r1 (see RFC 5639, section 3.4)
func P256r1() elliptic.Curve {
    once.Do(initAll)
    return p256r1
}

// P320t1 returns a Curve which implements Brainpool P320t1 (see RFC 5639, section 3.6)
func P320t1() elliptic.Curve {
    once.Do(initAll)
    return p320t1
}

// P320r1 returns a Curve which implements Brainpool P320r1 (see RFC 5639, section 3.6)
func P320r1() elliptic.Curve {
    once.Do(initAll)
    return p320r1
}

// P384t1 returns a Curve which implements Brainpool P384t1 (see RFC 5639, section 3.6)
func P384t1() elliptic.Curve {
    once.Do(initAll)
    return p384t1
}

// P384r1 returns a Curve which implements Brainpool P384r1 (see RFC 5639, section 3.6)
func P384r1() elliptic.Curve {
    once.Do(initAll)
    return p384r1
}

// P512t1 returns a Curve which implements Brainpool P512t1 (see RFC 5639, section 3.7)
func P512t1() elliptic.Curve {
    once.Do(initAll)
    return p512t1
}

// P512r1 returns a Curve which implements Brainpool P512r1 (see RFC 5639, section 3.7)
func P512r1() elliptic.Curve {
    once.Do(initAll)
    return p512r1
}
