package jceks

import (
    "io"
    "time"
    "encoding/binary"
)

func readUint8(r io.Reader) (uint8, error) {
    var v uint8
    err := binary.Read(r, binary.BigEndian, &v)

    return v, err
}

func writeUint8(w io.Writer, v uint8) error {
    return binary.Write(w, binary.BigEndian, v)
}

func readUint16(r io.Reader) (uint16, error) {
    var v uint16
    err := binary.Read(r, binary.BigEndian, &v)

    return v, err
}

func writeUint16(w io.Writer, v uint16) error {
    return binary.Write(w, binary.BigEndian, v)
}

func readInt32(r io.Reader) (int32, error) {
    var v int32
    err := binary.Read(r, binary.BigEndian, &v)

    return v, err
}

func writeInt32(w io.Writer, v int32) error {
    return binary.Write(w, binary.BigEndian, v)
}

func readUint32(r io.Reader) (uint32, error) {
    var v uint32
    err := binary.Read(r, binary.BigEndian, &v)

    return v, err
}

func writeUint32(w io.Writer, v uint32) error {
    return binary.Write(w, binary.BigEndian, v)
}

func readDate(r io.Reader) (time.Time, error) {
    var v int64
    err := binary.Read(r, binary.BigEndian, &v)
    if err != nil {
        return time.Time{}, err
    }

    sec := v / 1000
    nsec := (v - sec*1000) * 1000 * 1000

    return time.Unix(sec, nsec), nil
}

// 13位时间戳
func writeDate(w io.Writer, v time.Time) error {
    vv := v.UnixNano() / int64(time.Millisecond)

    return binary.Write(w, binary.BigEndian, int64(vv))
}

// readUTF reads a java encoded UTF-8 string. The encoding provides a
// 2-byte prefix indicating the length of the string.
func readUTF(r io.Reader) (string, error) {
    length, err := readUint16(r)
    if err != nil {
        return "", err
    }

    buf := make([]byte, length)

    _, err = io.ReadFull(r, buf)
    if err != nil {
        return "", err
    }

    return string(buf), nil
}

func writeUTF(w io.Writer, v string) error {
    length := len(v)

    err := writeUint16(w, uint16(length))
    if err != nil {
        return err
    }

    return binary.Write(w, binary.BigEndian, []byte(v))
}

// readBytes reads a byte array from the reader. The encoding provides
// a 4-byte prefix indicating the number of bytes which follow.
func readBytes(r io.Reader) ([]byte, error) {
    length, err := readInt32(r)
    if err != nil {
        return nil, err
    }

    buf := make([]byte, length)
    _, err = io.ReadFull(r, buf)
    if err != nil {
        return nil, err
    }

    return buf, nil
}

func writeBytes(w io.Writer, v []byte) error {
    length := len(v)

    err := writeInt32(w, int32(length))
    if err != nil {
        return err
    }

    return binary.Write(w, binary.BigEndian, v)
}

// 仅读取
func readOnly(r io.Reader, length int32) ([]byte, error) {
    buf := make([]byte, length)

    _, err := io.ReadFull(r, buf)
    if err != nil {
        return nil, err
    }

    return buf, nil
}

// 仅写入
func writeOnly(w io.Writer, v []byte) error {
    return binary.Write(w, binary.BigEndian, v)
}
