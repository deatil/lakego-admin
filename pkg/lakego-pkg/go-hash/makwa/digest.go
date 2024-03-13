package makwa

import (
    "bytes"
    "errors"
    "fmt"
    "strconv"
)

// A Digest is a hashed password.
type Digest struct {
    ModulusID   []byte
    Hash        []byte
    Salt        []byte
    WorkFactor  int
    PreHash     bool
    PostHashLen int
}

func (d *Digest) String() string {
    b, _ := d.MarshalText()
    return string(b)
}

// MarshalText marshals a digest into a text format.
func (d *Digest) MarshalText() ([]byte, error) {
    b := new(bytes.Buffer)

    _, _ = b.Write(b64Encode(d.ModulusID))
    _, _ = b.WriteRune('_')

    if d.PreHash {
        if d.PostHashLen > 0 {
            _, _ = b.WriteRune('b')
        } else {
            _, _ = b.WriteRune('r')
        }
    } else {
        if d.PostHashLen > 0 {
            _, _ = b.WriteRune('s')
        } else {
            _, _ = b.WriteRune('n')
        }
    }
    man, log, err := wfMant(uint32(d.WorkFactor))
    if err != nil {
        return nil, err
    }
    _, _ = b.WriteString(fmt.Sprintf(
        "%1d%02d",
        man,
        log,
    ))
    _, _ = b.WriteRune('_')

    _, _ = b.Write(b64Encode(d.Salt))
    _, _ = b.WriteRune('_')

    _, _ = b.Write(b64Encode(d.Hash))

    return b.Bytes(), nil
}

// UnmarshalText unmarshals a digest from a text format.
func (d *Digest) UnmarshalText(text []byte) error {
    parts := bytes.Split(text, []byte{'_'})

    var err error
    d.ModulusID, err = b64Decode(parts[0])
    if err != nil {
        return err
    }

    mantissa, err := strconv.Atoi(string(parts[1][1:2]))
    if err != nil {
        return err
    }

    log, err := strconv.Atoi(string(parts[1][2:]))
    if err != nil {
        return err
    }

    d.WorkFactor = 1
    for i := 0; i <= log; i++ {
        d.WorkFactor *= mantissa
    }

    d.Salt, err = b64Decode(parts[2])
    if err != nil {
        return err
    }

    d.Hash, err = b64Decode(parts[3])
    if err != nil {
        return err
    }

    switch parts[1][0] {
        case 'b':
            d.PreHash = true
            d.PostHashLen = len(d.Hash)
        case 'r':
            d.PreHash = true
            d.PostHashLen = 0
        case 's':
            d.PreHash = false
            d.PostHashLen = len(d.Hash)
        case 'n':
            d.PreHash = false
            d.PostHashLen = 0
    }

    return nil
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func b64Encode(b []byte) []byte {
    out := bytes.NewBuffer(make([]byte, 0, len(b)))
    for len(b) >= 3 {
        w := uint(b[0]) & 0xFF
        w = (w << 8) + (uint(b[1]) & 0xFF)
        w = (w << 8) + (uint(b[2]) & 0xFF)
        b = b[3:]

        _ = out.WriteByte(alphabet[w>>18])
        _ = out.WriteByte(alphabet[(w>>12)&0x3F])
        _ = out.WriteByte(alphabet[(w>>6)&0x3F])
        _ = out.WriteByte(alphabet[w&0x3F])
    }

    switch len(b) {
    case 1:
        w := uint(b[0]) & 0xFF
        _ = out.WriteByte(alphabet[w>>2])
        _ = out.WriteByte(alphabet[(w<<4)&0x3F])
    case 2:
        w := (uint(b[0]) & 0xFF) << 8
        w += uint(b[1]) & 0xFF
        _ = out.WriteByte(alphabet[w>>10])
        _ = out.WriteByte(alphabet[(w>>4)&0x3F])
        _ = out.WriteByte(alphabet[(w<<2)&0x3F])
    }

    return out.Bytes()
}

// ErrBadBase64 is returned when the provided Base64 value cannot be decoded.
var ErrBadBase64 = errors.New("bad base64")

func b64Decode(b []byte) ([]byte, error) {
    out := bytes.NewBuffer(make([]byte, 0, len(b)))
    var numEq, acc, k int32
    for i := range b {
        d := int32(b[i])
        if d >= 'A' && d <= 'Z' {
            d -= 'A'
        } else if d >= 'a' && d <= 'z' {
            d -= ('a' - 26)
        } else if d >= '0' && d <= '9' {
            d -= ('0' - 52)
        } else if d == '+' {
            d = 62
        } else if d == '/' {
            d = 63
        } else {
            return nil, ErrBadBase64
        }

        if d < 0 {
            d = 0
        } else {
            if numEq != 0 {
                return nil, ErrBadBase64
            }
        }
        acc = (acc << 6) + d
        k++
        if k == 4 {
            _ = out.WriteByte(byte((acc >> 16) | (acc << 16)))
            _ = out.WriteByte(byte((acc >> 8) | (acc << 24)))
            _ = out.WriteByte(byte(acc))
            acc = 0
            k = 0
        }
    }

    if k != 0 {

        if k == 1 {
            return nil, ErrBadBase64
        }

        switch k {
        case 2:
            _ = out.WriteByte(byte((acc >> 4) | (acc << 28)))
        case 3:
            _ = out.WriteByte(byte((acc >> 10) | (acc << 22)))
            _ = out.WriteByte(byte((acc >> 2) | (acc << 30)))
        }
    }

    return out.Bytes(), nil
}
