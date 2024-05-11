package bcd8421

import "testing"

func Test_Uint8toBCD(t *testing.T) {
    var tests = []struct {
        number uint8
        want   byte
    }{
        {0, 0x00},
        {1, 0x01},
        {2, 0x02},
        {3, 0x03},
        {4, 0x04},
        {5, 0x05},
        {6, 0x06},
        {7, 0x07},
        {8, 0x08},
        {9, 0x09},
        {10, 0x10},
        {11, 0x11},
        {12, 0x12},
        {13, 0x13},
        {14, 0x14},
        {15, 0x15},
        {16, 0x16},
        {17, 0x17},
        {18, 0x18},
        {19, 0x19},
        {20, 0x20},
    }
    for _, tt := range tests {
        res := Uint8toBCD(tt.number)
        if res != tt.want {
            t.Errorf("number %d; , want %2.2x, got %2.2x\n", tt.number, tt.want, res)
        }
    }
}

func Test_BCDtoUint8(t *testing.T) {
    var tests = []struct {
        input byte
        want  uint8
        err   error
    }{
        {0x00, 0, nil},
        {0x01, 1, nil},
        {0x02, 2, nil},
        {0x03, 3, nil},
        {0x04, 4, nil},
        {0x05, 5, nil},
        {0x06, 6, nil},
        {0x07, 7, nil},
        {0x08, 8, nil},
        {0x09, 9, nil},
        {0x10, 10, nil},
        {0x11, 11, nil},
        {0x12, 12, nil},
        {0x13, 13, nil},
        {0x14, 14, nil},
        {0x15, 15, nil},
        {0x16, 16, nil},
        {0x17, 17, nil},
        {0x18, 18, nil},
        {0x19, 19, nil},
        {0x20, 20, nil},
        {0x1a, 20, ErrNotBCD},
    }
    for _, tt := range tests {
        res, err := BCDtoUint8(tt.input)

        if res != tt.want || err != tt.err {
            t.Errorf("number %2x; , want %d, error %s got %d\n, err %v", tt.input, tt.want, tt.err, res, err)
        }
    }
}
