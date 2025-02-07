package base92

import (
    "bytes"
    "reflect"
    "testing"
)

var cases = []struct {
    name string
    bin  []byte
}{
    {"nil", nil},
    {"empty", []byte{}},
    {"zero", []byte{0}},
    {"one", []byte{1}},
    {"two", []byte{2}},
    {"ten", []byte{10}},
    {"2zeros", []byte{0, 0}},
    {"2ones", []byte{1, 1}},
    {"64zeros", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
    {"65zeros", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
    {"ascii", []byte("c'est une longue chanson")},
    {"utf8", []byte("Garçon, un café très fort !")},
}

func Test_Encode(t *testing.T) {
    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            str := StdEncoding.EncodeToString(c.bin)

            ni := len(c.bin)
            if ni > 70 {
                ni = 70 // print max the first 70 bytes
            }
            na := len(str)
            if na > 70 {
                na = 70 // print max the first 70 characters
            }
            t.Logf("bin len=%d [:%d]=%v", len(c.bin), ni, c.bin[:ni])
            t.Logf("str len=%d [:%d]=%q", len(str), na, str[:na])

            got, err := StdEncoding.DecodeString(str)
            if err != nil {
                t.Errorf("Decode() error = %v", err)
                return
            }

            ng := len(got)
            if ng > 70 {
                ng = 70 // print max the first 70 bytes
            }
            t.Logf("got len=%d [:%d]=%v", len(got), ng, got[:ng])

            if (len(got) == 0) && (len(c.bin) == 0) {
                return
            }

            if !reflect.DeepEqual(got, c.bin) {
                t.Errorf("Decode() = %v, want %v", got, c.bin)
            }
        })
    }
}

func Test_Encode2(t *testing.T) {
    for _, s := range SamplesStd {
        encoded := string(StdEncoding.Encode(s.sourceBytes))
        if len(encoded) == len(s.target) && encoded == s.target {
            t.Logf("source: %-15s\ttarget: %s", s.source, s.target)
        } else {
            t.Errorf("source: %-15s\texpected target: %s(%d)\tactual target: %s(%d)", s.source, s.target, len(s.target), encoded, len(encoded))
        }
    }
}

func Test_Decode2(t *testing.T) {
    for _, s := range SamplesStd {
        decoded, err := StdEncoding.Decode(s.targetBytes)
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

func Test_EncodeToString(t *testing.T) {
    for _, s := range SamplesStd {
        encoded := StdEncoding.EncodeToString([]byte(s.source))
        if len(encoded) == len(s.target) && encoded == s.target {
            t.Logf("source: %-15s\ttarget: %s", s.source, s.target)
        } else {
            t.Errorf("source: %-15s\texpected target: %s(%d)\tactual target: %s(%d)", s.source, s.target, len(s.target), encoded, len(encoded))
        }
    }
}

func Test_DecodeString(t *testing.T) {
    for _, s := range SamplesStd {
        decoded, err := StdEncoding.DecodeString(s.target)
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

func Test_EncodeWithCustomAlphabet(t *testing.T) {
    for _, s := range SamplesWithAlphabet {
        encoded := NewEncoding(s.alphabet).EncodeToString(s.sourceBytes)
        if encoded == s.target {
            t.Logf("source: %-15s\ttarget: %s", s.source, s.target)
        } else {
            str := string(encoded)
            t.Errorf("source: %-15s\texpected target: %s(%d)\tactual target: %s(%d)", s.source, s.target, len(s.target), str, len(str))
        }
    }
}

func Test_DecodeWithCustomAlphabet(t *testing.T) {
    for _, s := range SamplesWithAlphabet {
        decoded, err := NewEncoding(s.alphabet).DecodeString(s.target)
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
        decoded, err := StdEncoding.DecodeString(s.target)
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

// encodeStdTest use encodeStd to replace `;"` to ` '`
const encodeStdTest = " !#$%&'()*+,-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
const encodeStdTest2 = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}~"

type Sample struct {
    source      string
    target      string
    sourceBytes []byte
    targetBytes []byte
    alphabet    string
}

var SamplesStd = []*Sample{
    NewSample("", ""),
    NewSample("f", "1a"),
    NewSample("fo", "393"),
    NewSample("foo", "8VdP"),
    NewSample("foob", "n\"1=`"),
    NewSample("fooba", "=/o>zJ"),
    NewSample("foobar", "21!/2`*G"),

    NewSample("su", "3Jp"),
    NewSample("sur", "9+`>"),
    NewSample("sure", "r3U-1"),
    NewSample("sure.", "(m5^vq"),
    NewSample("asure.", "1#+m[Bem"),
    NewSample("easure.", "5PN!3(DX>"),
    NewSample("leasure.", "gN#iXt$=}e"),

    NewSample("=", "Z"),
    NewSample(">", "."),
    NewSample("?", "-"),
    NewSample("11", "1I@"),
    NewSample("111", "4c@|"),
    NewSample("1111", "bL{~5"),
    NewSample("11111", "w5iL>F"),
    NewSample("111111", "~iHN3eV"),

    NewSample("Hello, World!", "k3f/B6!rQL=RhJ?d"),
    NewSample("你好，世界！", "1m&5KqaKycjNt]Y8I0FkS:x"),
    NewSample("こんにちは", "5rIFEY^zgV@2jOj{s|z"),
    NewSample("안녕하십니까", "1q=eNur3aBy#78Cu:Zjn[`A"),

    NewSample(string([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255}), "01hQh.Jm{XcF^"),
}

var SamplesWithAlphabet = []*Sample{
    NewSampleWithAlphabet("", "", encodeStdTest),
    NewSampleWithAlphabet("f", "!+", encodeStdTest),
    NewSampleWithAlphabet("fo", "$*$", encodeStdTest),
    NewSampleWithAlphabet("foo", ")[.U", encodeStdTest),
    NewSampleWithAlphabet("foob", "8~!e}", encodeStdTest),
    NewSampleWithAlphabet("fooba", "eh9mEO", encodeStdTest),
    NewSampleWithAlphabet("foobar", "#!gh#}iL", encodeStdTest),

    NewSampleWithAlphabet("su", "$O:", encodeStdTest),
    NewSampleWithAlphabet("sur", "*d}m", encodeStdTest),
    NewSampleWithAlphabet("sure", "=$Zb!", encodeStdTest),
    NewSampleWithAlphabet("sure.", "n7&fA<", encodeStdTest),
    NewSampleWithAlphabet("asure.", "!wd7pG/7", encodeStdTest),
    NewSampleWithAlphabet("easure.", "&USg$nI^m", encodeStdTest),
    NewSampleWithAlphabet("leasure.", "1Sw3^?ves/", encodeStdTest),

    NewSampleWithAlphabet("=", "`", encodeStdTest),
    NewSampleWithAlphabet(">", "a", encodeStdTest),
    NewSampleWithAlphabet("?", "b", encodeStdTest),
    NewSampleWithAlphabet("11", "!Nt", encodeStdTest),
    NewSampleWithAlphabet("111", "%-tx", encodeStdTest),
    NewSampleWithAlphabet("1111", ",Qr|&", encodeStdTest),
    NewSampleWithAlphabet("11111", "B&3QmK", encodeStdTest),
    NewSampleWithAlphabet("111111", "|3MS$/[", encodeStdTest),

    NewSampleWithAlphabet("Hello, World!", "5$0hG'g=VQeW2Oj.", encodeStdTest),
    NewSampleWithAlphabet("你好，世界！", "!7k&P<+PD-4S?q_)N K5XcC", encodeStdTest),
    NewSampleWithAlphabet("こんにちは", "&=NKJ_fE1[t#4T4r>xE", encodeStdTest),
    NewSampleWithAlphabet("안녕하십니까", "!<e/S@=$+GDw()H@c`48p}F", encodeStdTest),

    // NewSampleWithAlphabet("hello world", "Fc_$aOTdKnsM*k", encodeStdTest2),
    // NewSampleWithAlphabet("你好", "sIb@Vyq8", encodeStdTest2),
}

var SamplesErr = []*Sample{
    NewSample("", "Hello, World!"),
    NewSample("", "哈哈"),
    NewSample("", "はは"),
}
