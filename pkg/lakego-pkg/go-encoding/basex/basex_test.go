package basex

import (
    "bytes"
    "testing"
    "reflect"
)

func Test_Encode(t *testing.T) {
    for _, s := range SamplesStd {
        encoded := Base62Encoding.EncodeToString([]byte(s.source))
        if len(encoded) == len(s.target) && encoded == s.target {
            t.Logf("source: %-15s\ttarget: %s", s.source, s.target)
        } else {
            t.Errorf("source: %-15s\texpected target: %s(%d)\tactual target: %s(%d)", s.source, s.target, len(s.target), encoded, len(encoded))
        }
    }
}

func Test_Decode(t *testing.T) {
    for _, s := range SamplesStd {
        decoded, err := Base62Encoding.DecodeString(s.target)
        if err != nil {
            t.Error(err)
            continue
        }

        if bytes.Equal(decoded, s.sourceBytes) {
            t.Logf("target: %-15s\tsource: %s", s.target, s.source)
        } else {
            str := string(decoded)
            t.Errorf("target: %-15s\texpected source: %s(%d)\tactual source: %s(%d)", s.target, s.source, len(s.source), str, len(str))
        }
    }
}

func Test_DecodeError(t *testing.T) {
    for _, s := range SamplesErr {
        decoded, err := Base62Encoding.DecodeString(s.target)
        if err != nil {
            t.Logf("%s: \"%c\"", err.Error(), err)
            continue
        }

        str := string(decoded)
        t.Errorf("An error should have occurred, instead of returning \"%s\"", str)
    }
}

func NewSample(source, target string) *Sample {
    return &Sample{source: source, target: target, sourceBytes: []byte(source), targetBytes: []byte(target)}
}

func NewSampleWithAlphabet(source, target, alphabet string) *Sample {
    return &Sample{source: source, target: target, sourceBytes: []byte(source), targetBytes: []byte(target), alphabet: alphabet}
}

type Sample struct {
    source      string
    target      string
    sourceBytes []byte
    targetBytes []byte
    alphabet    string
}

var SamplesStd = []*Sample{
    NewSample("", ""),
    NewSample("f", "1e"),
    NewSample("fo", "6ox"),
    NewSample("foo", "SAPP"),
    NewSample("foob", "1sIyuo"),
    NewSample("fooba", "7kENWa1"),
    NewSample("foobar", "VytN8Wjy"),

    NewSample("su", "7gj"),
    NewSample("sur", "VkRe"),
    NewSample("sure", "275mAn"),
    NewSample("sure.", "8jHquZ4"),
    NewSample("asure.", "UQPPAab8"),
    NewSample("easure.", "26h8PlupSA"),
    NewSample("leasure.", "9IzLUOIY2fe"),

    NewSample("=", "z"),
    NewSample(">", "10"),
    NewSample("?", "11"),
    NewSample("11", "3H7"),
    NewSample("111", "DWfh"),
    NewSample("1111", "tquAL"),
    NewSample("11111", "3icRuhV"),
    NewSample("111111", "FMElG7cn"),

    NewSample("Hello, World!", "1wJfrzvdbtXUOlUjUf"),
    NewSample("你好，世界！", "1ugmIChyMAcCbDRpROpAtpXdp"),
    NewSample("こんにちは", "1fyB0pNlcVqP3tfXZ1FmB"),
    NewSample("안녕하십니까", "1yl6dfHPaO9hroEXU9qFioFhM"),
}

var SamplesErr = []*Sample{
    NewSample("", "Hello, World!"),
    NewSample("", "哈哈"),
    NewSample("", "はは"),
}

func Test_Encode_Check(t *testing.T) {
    var cases = []struct {
        name string
        src  []byte
        enc  string
    }{
        {
            "index-1",
            []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255},
            "0rwg9z1idsugqv3",
        },
    }

    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            str := Base36Encoding.EncodeToString(c.src)
            if !reflect.DeepEqual(str, c.enc) {
                t.Errorf("EncodeToString() = %v, want %v", str, c.enc)
            }

            got, err := Base36Encoding.DecodeString(c.enc)
            if err != nil {
                t.Fatal(err)
            }

            if !reflect.DeepEqual(got, c.src) {
                t.Errorf("DecodeString() = %v, want %v", got, c.src)
            }
        })
    }
}
