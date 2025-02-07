package base91

import (
    "bytes"
    "testing"
)

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
    NewSample("f", "LB"),
    NewSample("fo", "drD"),
    NewSample("foo", "dr.J"),
    NewSample("foob", "dr/2Y"),
    NewSample("fooba", "dr/2s)A"),
    NewSample("foobar", "dr/2s)uC"),

    NewSample("su", "f8D"),
    NewSample("sur", "f8FK"),
    NewSample("sure", "f8zgZ"),
    NewSample("sure.", "f8zg5gA"),
    NewSample("asure.", "v2e3f,BB"),
    NewSample("easure.", "_D7gt@\"@C"),
    NewSample("leasure.", "XPH<2]6eOI"),

    NewSample("=", "9A"),
    NewSample(">", "!A"),
    NewSample("?", "#A"),
    NewSample("11", "hwB"),
    NewSample("111", "hwdE"),
    NewSample("1111", "hw;aM"),
    NewSample("11111", "hw;a2iA"),
    NewSample("111111", "hw;a2iHB"),

    NewSample("Hello, World!", ">OwJh>}AQ;r@@Y?F"),
    NewSample("你好，世界！", "I_5k7az}Thlz6;n[kjFVUBB"),
    NewSample("こんにちは", "cFs@CCLU=(Py|QE@4rF"),
    NewSample("안녕하십니까", "99v?OEn<ga&!l!?]DYLr{IB"),
}

var SamplesWithAlphabet = []*Sample{
    NewSampleWithAlphabet("", "", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("f", "LB", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("fo", "3hD", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("foo", "3h.J", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("foob", "3h/sY", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("fooba", "3h/si)A", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("foobar", "3h/si)kC", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),

    NewSampleWithAlphabet("su", "5yD", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("sur", "5yFK", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("sure", "5yp6Z", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("sure.", "5yp6v6A", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("asure.", "ls4t5,BB", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("easure.", "_Dx6j@\"@C", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("leasure.", "XPH<s]w4OI", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),

    NewSampleWithAlphabet("=", "zA", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet(">", "!A", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("?", "#A", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("11", "7mB", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("111", "7m3E", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("1111", "7m;0M", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("11111", "7m;0s8A", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("111111", "7m;0s8HB", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),

    NewSampleWithAlphabet("Hello, World!", ">OmJ7>}AQ;h@@Y?F", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("你好，世界！", "I_vax0p}T7bpw;d[a9FVUBB", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("こんにちは", "2Fi@CCLU=(Po|QE@uhF", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    NewSampleWithAlphabet("안녕하십니까", "zzl?OEd<60&!b!?]DYLh{IB", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
}

var SamplesErr = []*Sample{
    NewSample("", "Hello, World!"),
    NewSample("", "哈哈"),
    NewSample("", "はは"),
}
