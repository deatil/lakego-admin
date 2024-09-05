package rabin

import (
    "io"
    "fmt"
    "bytes"
    "math/big"
    "crypto/sha256"
    "encoding/binary"
)

func generateRabinPrimeNumber(rand io.Reader, bitLength int) *big.Int {
    temp := big.NewInt(0)
    p := big.NewInt(0)

    for {
        p = getprimeNumber(rand, bitLength)
        temp = temp.Mod(p, four)

        if temp.Cmp(three) == 0 {
            break
        }
    }

    return p
}

func getprimeNumber(rand io.Reader, bitLength int) (randomNumber *big.Int) {
    var resultWhetherPrime bool

    for {
        randomNumber = generateNumber(rand, bitLength)

        resultWhetherPrime = isaPrimeNumber(randomNumber, five)
        if resultWhetherPrime {
            return
        }
    }

    return
}

func generateNumber(rand io.Reader, bitLength int) *big.Int {
    b := make([]byte, bitLength)
    if _, err := io.ReadFull(rand, b); err != nil {
        return &big.Int{}
    }

    z := big.NewInt(0)

    return z.SetBytes(b)
}

func isaPrimeNumber(number *big.Int, accuracyFactor *big.Int) (bool) {
    if (big.NewInt(0).Mod(number, two)).Cmp(zero) == 0 {
        return false
    }

    varNumber := big.NewInt(0).Sub(number, one)

    r := big.NewInt(2)

    // exponentitalR is 2powr(r)
    exponentitalR := big.NewInt(2)

    for {
        x := big.NewInt(0)
        modValForX := big.NewInt(0)
        x, modValForX = x.DivMod(varNumber, exponentitalR, modValForX)

        if modValForX.Cmp(zero) == 0 {
            // Fixing value 10000000000 for calculation purpose
            // To resue the squareAndMultiple algorithm but not affect the modulo part
            r = r.Add(r, one)

            exponentitalR = squareAndMultiplyWithoutMod(two, r)
        } else {
            break
        }
    }

    r = r.Sub(r, one)

    exponentitalR = squareAndMultiplyWithoutMod(two, r)

    d := big.NewInt(0)
    d = d.Div(varNumber,exponentitalR)

    for i := big.NewInt(0); i.Cmp(accuracyFactor) == -1; i.Add(i, one) {
        millerRabinPrimalityTestResult := millerRabinPrimalityTest(number, d, r)
        if millerRabinPrimalityTestResult == false {
            return false
        }
    }

    return true
}

func squareAndMultiplyWithoutMod(number *big.Int, exponent *big.Int) *big.Int {
    value := big.NewInt(1)

    binExp := fmt.Sprintf("%b", exponent)
    binExpLength := len(binExp)

    if exponent.Cmp(one) == 0 {
        return number
    }

    for i := 1; i < binExpLength; i++ {
        if byte(binExp[i]) == byte(49) {
            value.Mul(value, value)
            value.Mul(value, number)
        } else {
            value.Mul(value, value)
        }
    }

    return value
}

func millerRabinPrimalityTest(number *big.Int, d *big.Int, r *big.Int) bool {
    numberTemp := big.NewInt(0)
    numberTemp = numberTemp.Sub(number, four)

    // aTemp := rand.Int63n(numberTemp.Int64()) + 2
    aTemp := int64(1000000000001)
    a := big.NewInt(aTemp)

    x := squareAndMultiple(a, d, number)

    numberMinusOne := big.NewInt(0).Sub(number, one)
    if x.Cmp(one) == 0 || x.Cmp(numberMinusOne) == 0 {
        return true
    }

    loopCount := big.NewInt(0).Sub(r, one)

    for i := big.NewInt(0); i.Cmp(loopCount) == -1; i.Add(i, one) {
        xIntermediate := big.NewInt(0).Mul(x, x)

        x = x.Mod(xIntermediate, number)
        if x.Cmp(one) == 0 {
            return false
        }

        if x.Cmp(numberMinusOne) == 0 {
            return true
        }
    }

    return false
}

func squareAndMultiple(a *big.Int, b *big.Int, c *big.Int) *big.Int {
    binExp := fmt.Sprintf("%b", b)
    binExpLength := len(binExp)

    initialValue := big.NewInt(0)
    initialValue = initialValue.Mod(a,c)

    result := big.NewInt(0)
    result = result.Set(initialValue)

    for i := 1; i < binExpLength; i++ {
        interMediateResult := big.NewInt(0)
        interMediateResult = interMediateResult.Mul(result,result)
        result = result.Mod(interMediateResult, c)

        if byte(binExp[i]) == byte(49) {
            interResult := big.NewInt(0)
            interResult = interResult.Mul(result, initialValue)
            result = result.Mod(interResult, c)
        }
    }

    return result
}

func extendedEuclideanAlgorithm(a *big.Int, b *big.Int) (*big.Int, *big.Int, *big.Int) {
    d := big.NewInt(0)
    x := big.NewInt(0)
    y := big.NewInt(0)

    if b.Cmp(zero) == 0 {
        d = d.Set(a)
        x = big.NewInt(1)
        y = big.NewInt(0)

        return d, x, y
    }

    //  2 as per the Handbook of Applied cryptography
    x2 := big.NewInt(1)
    x1 := big.NewInt(0)
    y2 := big.NewInt(0)
    y1 := big.NewInt(1)

    // Setting big.Ints for the loop as we can't simple add (or) multiply
    // like Integers
    q := big.NewInt(0)
    r := big.NewInt(0)
    qb := big.NewInt(0)
    qx1 := big.NewInt(0)
    qy1 := big.NewInt(0)

    for b.Cmp(zero) == 1 {
        // 3.1 as per the Handbook of Applied cryptography
        q = q.Div(a,b)
        r = r.Sub(a,qb.Mul(q,b))
        x = x.Sub(x2,qx1.Mul(q,x1))
        y = y.Sub(y2,qy1.Mul(q,y1))

        // 3.2 as per the Handbook of Applied cryptography
        a = a.Set(b)
        b = b.Set(r)
        x2 = x2.Set(x1)
        x1 = x1.Set(x)
        y2 = y2.Set(y1)
        y1 = y1.Set(y)
    }

    // 4 as per the Handbook of Applied cryptography

    d = d.Set(a)
    x = x.Set(x2)
    y = y.Set(y2)

    return d, x, y
}

func getSquareRoot(C *big.Int, val *big.Int) *big.Int {
    temp := big.NewInt(0)
    temp = temp.Add(val, one)
    temp = temp.Div(temp, four)

    mpOrmq := squareAndMultiple(C, temp, val)

    return mpOrmq
}

func decrypt(p *big.Int, q *big.Int, C *big.Int, N *big.Int) (
    *big.Int,
    *big.Int,
    *big.Int,
    *big.Int,
) {
    mp := getSquareRoot(C, p)
    mq := getSquareRoot(C, q)

    // Finding values of yp and yq as per the equation yp.p + yq.q = 1
    // Using the Extended Euclidean algorithm to do the same

    pCopy := big.NewInt(0)
    qCopy := big.NewInt(0)
    pCopy = pCopy.Set(p)
    qCopy = qCopy.Set(q)

    _, yp, yq := extendedEuclideanAlgorithm(pCopy,qCopy)

    // Handling the 2 statements required to calculate r, -r
    ypPmq := big.NewInt(0)
    // ypPmq = ypPmq.Mul(p,mq)
    ypPmq = ypPmq.Mul(yp, p)

    ypPmq = ypPmq.Mul(ypPmq, mq)

    yqQmp := big.NewInt(0)
    yqQmp = yqQmp.Mul(q,mp)
    yqQmp = yqQmp.Mul(yqQmp,yq)

    ypPmqPlusyqQmp := big.NewInt(0)
    ypPmqPlusyqQmp = ypPmqPlusyqQmp.Add(ypPmq,yqQmp)

    if ypPmqPlusyqQmp.Cmp(zero) == -1 {
        temp := big.NewInt(0)
        temp = temp.Abs(ypPmqPlusyqQmp)

        tempAbs := big.NewInt(0)
        tempAbs = tempAbs.Set(temp)

        temp = temp.Div(temp, N)
        temp = temp.Add(temp, one)
        temp = temp.Mul(temp, N)

        ypPmqPlusyqQmp = ypPmqPlusyqQmp.Add(ypPmqPlusyqQmp, temp)
    } else {
        ypPmqPlusyqQmp = ypPmqPlusyqQmp.Mod(ypPmqPlusyqQmp,N)
    }

    NegativeypPmqPlusyqQmp := big.NewInt(0)
    NegativeypPmqPlusyqQmp = NegativeypPmqPlusyqQmp.Sub(N,ypPmqPlusyqQmp)

    // Handling the 2 statements required to calculate s, -s

    ypPmqMinusyqQmp := big.NewInt(0)
    ypPmqMinusyqQmp = ypPmqMinusyqQmp.Sub(ypPmq,yqQmp)

    if ypPmqMinusyqQmp.Cmp(zero) == -1 {
        temp := big.NewInt(0)
        temp = temp.Abs(ypPmqMinusyqQmp)

        tempAbs := big.NewInt(0)
        tempAbs = tempAbs.Set(temp)

        temp = temp.Div(temp,N)
        temp = temp.Add(temp, one)
        temp = temp.Mul(temp,N)

        ypPmqMinusyqQmp = ypPmqMinusyqQmp.Add(ypPmqMinusyqQmp, temp)
    } else {
        ypPmqMinusyqQmp = ypPmqMinusyqQmp.Mod(ypPmqMinusyqQmp,N)
    }

    NegativeypPmqMinusyqQmp := big.NewInt(0)
    NegativeypPmqMinusyqQmp = NegativeypPmqMinusyqQmp.Sub(N,ypPmqMinusyqQmp)

    return ypPmqPlusyqQmp, NegativeypPmqPlusyqQmp, ypPmqMinusyqQmp, NegativeypPmqMinusyqQmp
}

func hashEqual(p *big.Int, h []byte, length int) (bool, []byte) {
    if p.BitLen() > length * 8 {
        return false, nil
    }

    data := p.FillBytes(make([]byte, length))

    hash := sha256.Sum256(data)
    if bytes.Equal(hash[:], h) {
        return true, data
    }

    return false, nil
}

func getu32(ptr []byte) uint32 {
    return binary.BigEndian.Uint32(ptr)
}

func putu32(ptr []byte, a uint32) {
    binary.BigEndian.PutUint32(ptr, a)
}
