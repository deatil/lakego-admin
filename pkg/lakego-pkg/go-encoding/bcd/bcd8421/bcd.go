package bcd8421

import "errors"

var ErrNotBCD = errors.New("Byte is Not BCD Encoded")

// uint8 to Packed BCD 8-4-2-1 One digit per nibble
func Uint8toBCD(u uint8) byte {
    lsn := u % 10
    u /= 10
    msn := u % 10
    return ((msn & 0xf) << 4) | (lsn & 0xf)
}

// Packed BCD 8-4-2-1 One digit per nibble to uint8
// Error if not a BCD digits
func BCDtoUint8(bcd byte) (uint8, error) {
    digits := uint8((bcd>>4&0xf)*10 + (bcd & 0xf))

    // Confirm input is BCD encoded as expected
    check := Uint8toBCD(digits)

    if bcd != check|bcd {
        return digits, ErrNotBCD
    }

    return digits, nil
}
