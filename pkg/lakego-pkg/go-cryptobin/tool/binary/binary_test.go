package binary

import (
    "io"
    "testing"
    "crypto/rand"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool/test"
)

func Test_LE2BE_16(t *testing.T) {
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    data := make([]byte, 2)
    io.ReadFull(rand.Reader, data)

    enData := LE2BE_16(data)
    assertNotEmpty(enData, "LE2BE_16")

    enInt := binary.BigEndian.Uint16(enData[:])
    oldInt := binary.LittleEndian.Uint16(data[:])

    assertEqual(enInt, oldInt, "LE2BE_16")
}

func Test_BE2LE_16(t *testing.T) {
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    data := make([]byte, 2)
    io.ReadFull(rand.Reader, data)

    enData := BE2LE_16(data)
    assertNotEmpty(enData, "BE2LE_16")

    enInt := binary.LittleEndian.Uint16(enData[:])
    oldInt := binary.BigEndian.Uint16(data[:])

    assertEqual(enInt, oldInt, "BE2LE_16")
}

func Test_LE2BE_32(t *testing.T) {
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    data := make([]byte, 4)
    io.ReadFull(rand.Reader, data)

    enData := LE2BE_32(data)
    assertNotEmpty(enData, "LE2BE_32")

    enInt := binary.BigEndian.Uint32(enData[:])
    oldInt := binary.LittleEndian.Uint32(data[:])

    assertEqual(enInt, oldInt, "LE2BE_32")
}

func Test_BE2LE_32(t *testing.T) {
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    data := make([]byte, 4)
    io.ReadFull(rand.Reader, data)

    enData := BE2LE_32(data)
    assertNotEmpty(enData, "BE2LE_32")

    enInt := binary.LittleEndian.Uint32(enData[:])
    oldInt := binary.BigEndian.Uint32(data[:])

    assertEqual(enInt, oldInt, "BE2LE_32")
}

func Test_LE2BE_64(t *testing.T) {
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    data := make([]byte, 8)
    io.ReadFull(rand.Reader, data)

    enData := LE2BE_64(data)
    assertNotEmpty(enData, "LE2BE_64")

    enInt := binary.BigEndian.Uint64(enData[:])
    oldInt := binary.LittleEndian.Uint64(data[:])

    assertEqual(enInt, oldInt, "LE2BE_64")
}

func Test_BE2LE_64(t *testing.T) {
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    data := make([]byte, 8)
    io.ReadFull(rand.Reader, data)

    enData := BE2LE_64(data)
    assertNotEmpty(enData, "BE2LE_64")

    enInt := binary.LittleEndian.Uint64(enData[:])
    oldInt := binary.BigEndian.Uint64(data[:])

    assertEqual(enInt, oldInt, "BE2LE_64")
}

func Test_16_Bytes(t *testing.T) {
    assertNotEmpty := test.AssertNotEmptyT(t)

    data := make([]byte, 32)
    io.ReadFull(rand.Reader, data)

    enData := LE2BE_16_Bytes(data)
    assertNotEmpty(enData, "LE2BE_16_Bytes")

    deData := BE2LE_16_Bytes(data)
    assertNotEmpty(deData, "BE2LE_16_Bytes")
}

func Test_32_Bytes(t *testing.T) {
    assertNotEmpty := test.AssertNotEmptyT(t)

    data := make([]byte, 128)
    io.ReadFull(rand.Reader, data)

    enData := LE2BE_32_Bytes(data)
    assertNotEmpty(enData, "LE2BE_32_Bytes")

    deData := BE2LE_32_Bytes(data)
    assertNotEmpty(deData, "LE2BE_32_Bytes")
}

func Test_64_Bytes(t *testing.T) {
    assertNotEmpty := test.AssertNotEmptyT(t)

    data := make([]byte, 128)
    io.ReadFull(rand.Reader, data)

    enData := LE2BE_64_Bytes(data)
    assertNotEmpty(enData, "LE2BE_64_Bytes")

    deData := BE2LE_64_Bytes(data)
    assertNotEmpty(deData, "BE2LE_64_Bytes")
}
