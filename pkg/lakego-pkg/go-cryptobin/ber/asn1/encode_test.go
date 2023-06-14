package asn1

import (
    "bytes"
    "encoding/hex"
    "testing"
    "time"
)

type intStruct struct {
    A int
}

type twoIntStruct struct {
    A int
    B int
}

type nestedStruct struct {
    A intStruct
}

type implicitTagTest struct {
    A int `asn1:"tag:5"`
}

type explicitTagTest struct {
    A int `asn1:"explicit,tag:5"`
}

type generalizedTimeTest struct {
    A time.Time `asn1:"generalized"`
}

type ia5StringTest struct {
    A string `asn1:"ia5"`
}

type printableStringTest struct {
    A string `asn1:"printable"`
}

type applicationTest struct {
    A int `asn1:"application,tag:0"`
    B int `asn1:"application,tag:1,explicit"`
}

type optionalTest struct {
    X int `asn1:"optional"`
    Y int `asn1:"optional"`
}

type optional2Test struct {
    A int    `asn1:"optional"`
    B string `asn1:"octet"`
    C bool
}

type optionalTaggedTest struct {
    X int `asn1:"optional,tag:0"`
    Y int `asn1:"optional,tag:1"`
}

type numericStringTest struct {
    A string `asn1:"numeric"`
}

type privateTest struct {
    A int `asn1:"private,tag:0"`
    B int `asn1:"private,tag:1,explicit"`
    C int `asn1:"private,tag:31"`
    D int `asn1:"private,tag:128"`
}

type defaultTest struct {
    A int `asn1:"default:1"`
}

type omitEmptyTest struct {
    A []string `asn1:"omitempty,printable"`
}

type choiceTest struct {
    Name   string `asn1:"visible"`
    Nobody Null
}

type choice2Test struct {
    Name  string       `asn1:"octet"`
    Value choice2Value `asn1:"choice"`
}

type choice2Value struct {
    BooleanValue bool
    IntegerValue int
    StringValue  string `asn1:"octet"`
}

type choice3Test struct {
    Name  string       `asn1:"octet"`
    Value choice3Value `asn1:"choice"`
}

type choice3Value struct {
    StringValue string `asn1:"tag:0,octet"`
    BinaryValue string `asn1:"tag:1,octet"`
}

type choice4Test struct {
    Name  string       `asn1:"tag:0,octet"`
    Value choice4Value `asn1:"tag:1,choice,optional"`
}

type choice4Value struct {
    BooleanValue bool   `asn1:"tag:2"`
    IntegerValue int    `asn1:"tag:3"`
    StringValue  string `asn1:"tag:4,octet"`
    BinaryValue  []byte `asn1:"tag:5"`
}

type sequenceTest struct {
    Age    int
    Single bool
}

type sequence2Test struct {
    Name string `asn1:"ia5"`
    Ok   bool
}

type marshalTest struct {
    in  interface{}
    out string
}

var PST = time.FixedZone("PST", -8*60*60)

var marshalTests = []marshalTest{
    // BOOLEAN
    {true, "0101ff"},
    {false, "010100"},

    // strings
    {"", "0c00"},
    {"a", "0c0161"},
    {"abc", "0c03616263"},
    {"😎", "0c04f09f988e"},
    {"Σ", "0c02cea3"},
    {numericStringTest{"1 9"}, "30051203312039"},

    // OBJECT IDENTIFIER
    {ObjectIdentifier{0, 39}, "060127"},
    {ObjectIdentifier{1, 0}, "060128"},
    {ObjectIdentifier{1, 39}, "06014f"},
    {ObjectIdentifier{2, 0}, "060150"},
    {ObjectIdentifier{2, 39}, "060177"},
    {ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, "06092a864886f70d01010b"},
    {ObjectIdentifier{1, 2, 840, 113549}, "06062a864886f70d"},
    {ObjectIdentifier{1, 2, 3, 4}, "06032a0304"},
    {ObjectIdentifier{1, 2, 840, 133549, 1, 1, 5}, "06092a864888932d010105"},
    {ObjectIdentifier{2, 100, 3}, "0603813403"},

    // OCTET STRING
    {[]byte{0x03, 0x02, 0x06, 0xa0}, "0404030206a0"},
    {[]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}, "04080123456789abcdef"},
    {[]byte("Hello!"), "040648656c6c6f21"},
    {[]byte{}, "0400"},
    {[]byte{0x00}, "040100"},
    {[]byte{0x01, 0x02, 0x03}, "0403010203"},
    {[]byte{1, 2, 3}, "0403010203"},
    {[]byte{0x03, 0x02, 0x06, 0xa0}, "0404030206A0"},

    // REAL
    // TODO

    // INTEGER
    {-32769, "0203ff7fff"},
    {-32768, "02028000"},
    {-12345, "0202cfc7"},
    {-1000, "0202fc18"},
    {-256, "0202ff00"},
    {-129, "0202ff7f"},
    {-128, "020180"},
    {-1, "0201ff"},
    {0, "020100"},
    {1, "020101"},
    {10, "02010a"},
    {50, "020132"},
    {127, "02017f"},
    {128, "02020080"},
    {255, "020200ff"},
    {256, "02020100"},
    {-128, "020180"},
    {-129, "0202ff7f"},
    {1000, "020203e8"},
    {32767, "02027fff"},
    {32768, "0203008000"},
    {50000, "020300c350"},

    // NULL
    {Null{}, "0500"},

    // SEQUENCE
    {intStruct{64}, "3003020140"},
    {twoIntStruct{64, 65}, "3006020140020141"},
    {nestedStruct{intStruct{127}}, "3005300302017f"},
    {ia5StringTest{"test"}, "3006160474657374"},
    {printableStringTest{"test"}, "3006130474657374"},
    {applicationTest{1, 2}, "30084001016103020102"},
    {sequenceTest{24, true}, "30060201180101ff"},
    {sequence2Test{"Smith", true}, "300a1605536d6974680101ff"},

    // SEQUENCE OF
    {[]int{2, 6, 5}, "3009020102020106020105"},

    // OPTIONAL
    {optionalTest{X: 9}, "3003020109"},
    {optionalTaggedTest{X: 9}, "3003800109"},
    {optionalTaggedTest{Y: 9}, "3003810109"},
    {optionalTaggedTest{X: 9, Y: 9}, "3006800109810109"},
    {optional2Test{0, "abc", true}, "300804036162630101ff"},

    // implicit/explicit
    {implicitTagTest{64}, "3003850140"},
    {explicitTagTest{64}, "3005a503020140"},

    // private
    {privateTest{1, 2, 3, 4}, "3011c00101e103020102df1f0103df81000104"},

    // time
    {time.Unix(0, 0).UTC(), "17113730303130313030303030302b30303030"},
    {time.Unix(1258325776, 0).UTC(), "17113039313131353232353631362b30303030"},
    {time.Unix(1258325776, 0).In(PST), "17113039313131353134353631362d30383030"},
    // {farFuture(), "180f32313030303430353132303130315a"}, // generalized time?
    {generalizedTimeTest{time.Unix(1258325776, 0).UTC()}, "3011180f32303039313131353232353631365a"},
    {time.Date(1991, time.May, 6, 23, 45, 40, 0, time.UTC), "17113931303530363233343534302b30303030"},

    // BIT STRING
    {BitString{[]byte{0x80}, 7}, "03020780"},
    {BitString{[]byte{0x81, 0xf0}, 4}, "03030481f0"},
    {BitString{[]byte{0b01101110, 0b01011101, 0b11000000}, 6}, "0304066e5dc0"},
    {BitString{[]byte{}, 0}, "030100"},
    {BitString{[]byte{0x40}, 4}, "03020440"},
    {BitString{[]byte{0x80}, 7}, "03020780"},
    {BitString{[]byte{0x00, 0x00}, 7}, "0303070000"},
    {BitString{[]byte{0xe0}, 5}, "030205e0"},
    {BitString{[]byte{0x01}, 0}, "03020001"},

    // omitempty
    {omitEmptyTest{[]string{}}, "3000"},
    {omitEmptyTest{[]string{"1"}}, "30053003130131"},

    // DEFAULT
    {defaultTest{0}, "3003020100"},
    {defaultTest{1}, "3000"},
    {defaultTest{2}, "3003020102"},

    {[]int{0, 1, 2}, "3009020100020101020102"},
    {[...]int{0, 1, 2}, "3009020100020101020102"},
}

func TestMarshal(t *testing.T) {
    for i, test := range marshalTests {
        data, err := Marshal(test.in)
        if err != nil {
            t.Errorf("#%d failed: %s", i, err)
        }
        out, _ := hex.DecodeString(test.out)
        if !bytes.Equal(out, data) {
            t.Errorf("#%d got: %x want %x\n\t%q\n\t%q", i, data, out, data, out)
        }
    }
}

type marshalWithOptionsTest struct {
    in      interface{}
    out     string
    options string
}

var marshalWithOptionsTests = []marshalWithOptionsTest{
    // strings
    {"hi", "13026869", "printable"},
    {"Test User 1", "130b5465737420557365722031", "printable"},
    {"test1@rsa.com", "160d7465737431407273612e636f6d", "ia5"},
    {"hi", "16026869", "ia5"},
    {"hi", "85026869", "tag:5"},
    {"hi", "A5040C026869", "tag:5,explicit"},
    {
        "" +
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // 127 times 'x'
        "137f" +
            "7878787878787878787878787878787878787878787878787878787878787878" +
            "7878787878787878787878787878787878787878787878787878787878787878" +
            "7878787878787878787878787878787878787878787878787878787878787878" +
            "78787878787878787878787878787878787878787878787878787878787878",
        "printable",
    },
    {
        "" +
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // 128 times 'x'
        "138180" +
            "7878787878787878787878787878787878787878787878787878787878787878" +
            "7878787878787878787878787878787878787878787878787878787878787878" +
            "7878787878787878787878787878787878787878787878787878787878787878" +
            "7878787878787878787878787878787878787878787878787878787878787878",
        "printable",
    },
    {"test", "130474657374", "printable"},

    // time
    {time.Date(2019, time.December, 15, 19, 0o2, 10, 0, time.FixedZone("UTC-8", -8*60*60)), "17113139313231353139303231302d30383030", "utc"},
    {time.Date(1991, time.May, 6, 16, 45, 40, 0, time.FixedZone("UTC-8", -7*60*60)), "17113931303530363136343534302D30373030", "utc"},

    // enumerated
    {0, "0a0100", "enumerated"},

    // explicit
    {true, "a2030101ff", "tag:2,explicit"},
    {1, "a203020101", "tag:2,explicit"},
    {BitString{[]byte{0x56}, 1}, "a20403020156", "tag:2,explicit"},
    {[]byte{0x56}, "a203040156", "tag:2,explicit"},
    {"Jones", "1a054a6f6e6573", "visible"},
    {"Jones", "43054a6f6e6573", "visible,application,tag:3"},
    // {prefixedTest{"Jones"}, "a20743054a6f6e6573", "explicit,tag:2"}, // END

    // implicit
    {true, "8201ff", "tag:2"},
    {1, "820101", "tag:2"},

    // set
    {intStruct{10}, "310302010a", "set"},
    // application
    {intStruct{10}, "600302010a", "application"},
    // private
    {intStruct{10}, "e00302010a", "private"},

    // choice
    {choiceTest{Name: "Perec"}, "1a055065726563", "choice"},
    {choice2Test{Name: "age", Value: choice2Value{IntegerValue: 35}}, "30080403616765020123", ""},
    {choice3Test{Name: "hello", Value: choice3Value{StringValue: "there"}}, "300e040568656c6c6f80057468657265", ""},
    {choice4Test{Name: "state", Value: choice4Value{StringValue: "Texas"}}, "301080057374617465A10784055465786173", ""},
}

func TestMarshalWithOptions(t *testing.T) {
    for i, test := range marshalWithOptionsTests {
        data, err := MarshalWithOptions(test.in, test.options)
        if err != nil {
            t.Errorf("#%d failed: %s", i, err)
        }
        out, _ := hex.DecodeString(test.out)
        if !bytes.Equal(out, data) {
            t.Errorf("#%d got: %x want %x\n\t%q\n\t%q", i, data, out, data, out)
        }
    }
}

func assertBytesEqual(t *testing.T, expected []byte, actual []byte) {
    t.Helper()
    n := bytes.Compare(expected, actual)
    if n != 0 {
        t.Fatalf("Not equal: \n"+
            "expected: % x\n"+
            "actual: % x", expected, actual)
    }
}

func TestEncodeLength(t *testing.T) {
    shortForm1 := encodeLength(5)
    assertBytesEqual(t, []byte{0x05}, shortForm1)

    shortForm2 := encodeLength(123)
    assertBytesEqual(t, []byte{0x7b}, shortForm2)

    longForm1 := encodeLength(500)
    assertBytesEqual(t, []byte{0x82, 0x01, 0xf4}, longForm1)

    longForm2 := encodeLength(1234)
    assertBytesEqual(t, []byte{0x82, 0x04, 0xd2}, longForm2)

    longForm3 := encodeLength(201)
    assertBytesEqual(t, []byte{0x81, 0xc9}, longForm3)
}

func BenchmarkMarshal(b *testing.B) {
    b.ReportAllocs()

    for i := 0; i < b.N; i++ {
        for _, test := range marshalTests {
            Marshal(test.in)
        }
    }
}
