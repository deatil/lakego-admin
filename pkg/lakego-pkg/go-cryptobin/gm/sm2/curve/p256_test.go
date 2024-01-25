package curve

import (
    "fmt"
    "testing"
    "math/big"
)

func Test_sm2Curve_Add(t *testing.T) {
    var x1, y1, x2, y2 *big.Int

    x1, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    y1, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
    x2, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
    y2, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)

    r1, r2 := P256().Add(x1, y1, x2, y2)

    check := "a703722360c97e4a94bbbeb815b47f72b4ea8b65a38d22dccc6d55a2e97c5be5-c4ac0b4d328cb7f877d39c552638e9b01c3c747c413b220daced884ef72f5151"
    got := fmt.Sprintf("%x-%x", r1.Bytes(), r2.Bytes())

    if got != check {
        t.Errorf("Add error, got %s, want %s", got, check)
    }
}
