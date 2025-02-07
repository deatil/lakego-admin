package bcd

import (
    "errors"
)

func Encode(dataIn []byte) (out []byte) {
    dataInLen := len(dataIn)

    var posIn int = 0
    var posOut int = 0
    var nibbleFlag byte = 0
    var c byte = 0

    out = make([]byte, (dataInLen/2))

    for ; posIn < dataInLen; posIn++ {
        c = dataIn[posIn]

        if c >= '0' && c <= '9' {
            c -= '0'
        } else {
            switch {
                case c == 'A' || c == 'a':
                    c = 0x0a
                case c == 'B' || c == 'b':
                    c = 0x0b
                case c == 'C' || c == 'c':
                    c = 0x0c
                case c == 'D' || c == 'd':
                    c = 0x0d
                case c == 'E' || c == 'e':
                    c = 0x0e
                case c == 'F' || c == 'f':
                    c = 0x0f
                default:
                   return nil
            }
        }

        if nibbleFlag == 0 {
            c <<= 4
            out[posOut] |= c
            nibbleFlag = 1
        } else {
            out[posOut] |= c
            posOut++
            nibbleFlag = 0
        }
    }

    return
}

func Decode(dataIn []byte) (out []byte) {
    dataInLen := len(dataIn)

    var posIn int = 0
    var posOut int = 0

    out = make([]byte, (dataInLen*2))

    for ; posIn < dataInLen; posIn++ {
        out[posOut] = nibbleToHexChar(dataIn[posIn] >> 4)
        posOut++

        out[posOut] = nibbleToHexChar(dataIn[posIn] & 0x0f)
        posOut++
    }

    return
}

func nibbleToHexChar(nibble byte) byte {
    if (nibble >= 0) && (nibble <= 9) {
        return nibble + '0'
    } else {
        switch {
            case nibble == 0x0a:
                return 'a'
            case nibble == 0x0b:
                return 'b'
            case nibble == 0x0c:
                return 'c'
            case nibble == 0x0d:
                return 'd'
            case nibble == 0x0e:
                return 'e'
            case nibble == 0x0f:
                return 'f'
            default:
                return ' '
        }
    }
}

// =======

func CheckBCD(BCDvalue uint32) bool {
    for i := 0; i < 8; i++ {
        if (BCDvalue & 0x0F) > 0x09 {
            return false
        }

        BCDvalue >>= 4
    }

    return true
}

func Uint32ToBCD(BinaryValue uint32) (uint32, error) {
    if BinaryValue <= 99999999 {
        var ValueToReturn uint32 = 0
        var factor uint32 = 10000000

        for i := 0; i < 8; i++ {
            ValueToReturn <<= 4

            var temp uint32 = BinaryValue

            temp /= factor
            ValueToReturn |= temp

            temp *= factor
            BinaryValue -= temp
            factor /= 10;
        }

        return ValueToReturn, nil
    } else {
        return BinaryValue, errors.New("go-encoding/bcd: bad")
    }
}

func BCDtoUint32(CurrentBCDvalue uint32) (uint32, error) {
    if !CheckBCD(CurrentBCDvalue) {
        return CurrentBCDvalue, errors.New("go-encoding/bcd: bad")
    }

    var ValueToReturn uint32 = 0
    var factor uint32 = 1

    for i := 0; i < 8; i++ {
        var temp uint32 = CurrentBCDvalue
        temp &= 0x0F
        temp *= factor
        ValueToReturn += temp
        CurrentBCDvalue >>= 4
        factor *= 10
    }

    return ValueToReturn, nil
}
