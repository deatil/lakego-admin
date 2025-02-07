package base36

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

type Sample struct {
    source      string
    target      string
    sourceBytes []byte
    targetBytes []byte
    alphabet    string
}

var SamplesStd = []*Sample{
    NewSample("", ""),
    NewSample("f", "2u"),
    NewSample("fo", "k8f"),
    NewSample("foo", "3zvxr"),
    NewSample("foob", "sf742q"),
    NewSample("fooba", "5m42kzfl"),
    NewSample("foobar", "13x8yd7ywi"),

    NewSample("su", "mt1"),
    NewSample("sur", "4i6ia"),
    NewSample("sure", "w1aa1x"),
    NewSample("sure.", "6bt53hny"),
    NewSample("asure.", "11zbcm20j2"),
    NewSample("easure.", "7sz7l367x2m"),
    NewSample("leasure.", "1ncbu0pxvv6em"),

    NewSample("=", "1p"),
    NewSample(">", "1q"),
    NewSample("?", "1r"),
    NewSample("11", "9pt"),
    NewSample("111", "1x3jl"),
    NewSample("1111", "dnd7ap"),
    NewSample("11111", "2p25vw35"),
    NewSample("111111", "j67dus6cx"),

    NewSample("Hello, World!", "fg3h7vqw7een6jwwnzmp"),
    NewSample("你好，世界！", "j0sguou3jtppn6fagdqrb3kre1z5"),
    NewSample("こんにちは", "1w6pjye0qjvyw4xul6ds5jfz"),
    NewSample("안녕하십니까", "jo9sbh1ov904nwwy5gosugf1cmfg"),

    NewSample(string([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255}), "0rwg9z1idsugqv3"),
}

var SamplesWithAlphabet = []*Sample{
    NewSampleWithAlphabet("", "", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("f", "2a", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("fo", "q8l", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("foo", "3fbdx", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("foob", "yl742w", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("fooba", "5s42qflr", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("foobar", "13d8ej7eco", "0123456789ghijklmnopqrstuvwxyzabcdef"),

    NewSampleWithAlphabet("su", "sz1", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("sur", "4o6og", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("sure", "c1gg1d", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("sure.", "6hz53nte", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("asure.", "11fhis20p2", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("easure.", "7yf7r367d2s", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("leasure.", "1tiha0vdbb6ks", "0123456789ghijklmnopqrstuvwxyzabcdef"),

    NewSampleWithAlphabet("=", "1v", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet(">", "1w", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("?", "1x", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("11", "9vz", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("111", "1d3pr", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("1111", "jtj7gv", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("11111", "2v25bc35", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("111111", "p67jay6id", "0123456789ghijklmnopqrstuvwxyzabcdef"),

    NewSampleWithAlphabet("Hello, World!", "lm3n7bwc7kkt6pcctfsv", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("你好，世界！", "p0ymaua3pzvvt6lgmjwxh3qxk1f5", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("こんにちは", "1c6vpek0wpbec4dar6jy5plf", "0123456789ghijklmnopqrstuvwxyzabcdef"),
    NewSampleWithAlphabet("안녕하십니까", "pu9yhn1ub904tcce5muyaml1islm", "0123456789ghijklmnopqrstuvwxyzabcdef"),
}

var SamplesErr = []*Sample{
    NewSample("", "Hello, World!"),
    NewSample("", "哈哈"),
    NewSample("", "はは"),
}
