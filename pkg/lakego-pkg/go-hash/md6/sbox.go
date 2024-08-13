package md6

const b = 512
const c = 128
const n = 89

var S0 = []uint32{0x01234567, 0x89ABCDEF}
var Sm = []uint32{0x7311C281, 0x2425CFA0}

var Q = [][]uint32{
    {0x7311C281, 0x2425CFA0},
    {0x64322864, 0x34AAC8E7},
    {0xB60450E9, 0xEF68B7C1},
    {0xE8FB2390, 0x8D9F06F1},
    {0xDD2E76CB, 0xA691E5BF},
    {0x0CD0D63B, 0x2C30BC41},
    {0x1F8CCF68, 0x23058F8A},
    {0x54E5ED5B, 0x88E3775D},
    {0x4AD12AAE, 0x0A6D6031},
    {0x3E7F16BB, 0x88222E0D},
    {0x8AF8671D, 0x3FB50C2C},
    {0x995AD117, 0x8BD25C31},
    {0xC878C1DD, 0x04C4B633},
    {0x3B72066C, 0x7A1552AC},
    {0x0D6F3522, 0x631EFFCB},
}

var t = []int{17, 18, 21, 31, 67, 89}
var rs = []int{10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12}
var ls = []int{11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9}

