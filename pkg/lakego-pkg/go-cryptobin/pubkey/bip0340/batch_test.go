package bip0340

import (
    "fmt"
    "testing"
    "math/big"
    "crypto/sha256"
    "crypto/elliptic"
)

func Test_Batch_Check(t *testing.T) {
    var pks []*PublicKey
    var ms, sigs [][]byte

    for i, td := range testSigVecBatch {
        t.Run(fmt.Sprintf("index %d", i), func(t *testing.T) {
            pubBytes := append([]byte{byte(3)}, td.publicKey...)

            x, y := elliptic.UnmarshalCompressed(S256(), pubBytes)
            if x == nil || y == nil {
                t.Fatal("publicKey error")
            }

            pubkey := &PublicKey{
                Curve: S256(),
                X: x,
                Y: y,
            }

            pks = append(pks, pubkey)
            ms = append(ms, td.message)
            sigs = append(sigs, td.signature)
        })
    }

    res := BatchVerify(pks, ms, sigs, sha256.New)
    if !res {
        t.Errorf("Batch verify failed")
    }
}

var testSigVecBatch = []testVec{
    {
        secretKey: fromHex("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"),
        publicKey: fromHex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
        auxRand:   fromHex("01"),
        message:   fromHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
        signature: fromHex("6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
        verification: true,
    },
    {
        secretKey: fromHex("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"),
        publicKey: fromHex("DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"),
        auxRand:   fromHex("C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906"),
        message:   fromHex("7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"),
        signature: fromHex("5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"),
        verification: true,
    },
    {
        secretKey: fromHex("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710"),
        publicKey: fromHex("25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"),
        auxRand:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        message:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        signature: fromHex("7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"),
        verification: true,
    },

}

func Test_Bit(t *testing.T) {
    a := byte(1)

    res1 := a | 2
    res2 := res1&1

    if res2 != a {
        t.Errorf("want %d, got %d \n", a, res2)
    }
}

func Test_Bigint_Bit(t *testing.T) {
    a := new(big.Int).SetBytes([]byte("7234567"))

    res1 := byte(a.Bit(0)) | 2
    res2 := res1&1

    b := new(big.Int).Set(a)
    b.Neg(b)

    if res2 != byte(a.Bit(0)) {
        t.Errorf("want %d, got %d \n", byte(a.Bit(0)), res2)
    }

    if res2 != byte(b.Bit(0)) {
        t.Errorf("2 want %d, got %d \n", byte(a.Bit(0)), res2)
    }
}
