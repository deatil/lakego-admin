package file

import (
    "os"
    "io"
    "fmt"
    "errors"
    "bufio"
    "crypto/md5"
    "crypto/sha1"
)

// 文件 Md5
func Md5(filename string) (string, error) {
    openfile, err := os.Open(filename)
    if err != nil {
        return "", err
    }
    defer openfile.Close()

    return Md5WithOsOpen(openfile)
}

// 文件 Md5
func Md5WithOsOpen(openfile *os.File) (string, error) {
    hash := md5.New()
    _, err := io.Copy(hash, openfile)
    if nil != err {
        return "", err
    }

    sum := hash.Sum(nil)

    return fmt.Sprintf("%x", sum), nil
}

// 大文件 Md5
func Md5ForBig(filename string) (string, error) {
    if info, err := os.Stat(filename); err != nil {
        return "", err
    } else if info.IsDir() {
        return "", errors.New("不是文件无法计算")
    }

    openfile, err := os.Open(filename)
    if err != nil {
        return "", err
    }
    defer openfile.Close()

    return Md5ForBigWithOsOpen(openfile)
}

// 大文件 Md5
func Md5ForBigWithOsOpen(openfile *os.File) (string, error) {
    const bufferSize = 65536

    hash := md5.New()
    for buf, reader := make([]byte, bufferSize), bufio.NewReader(openfile); ; {
        n, err := reader.Read(buf)
        if err != nil {
            if err == io.EOF {
                break
            }
            return "", err
        }

        hash.Write(buf[:n])
    }

    checksum := fmt.Sprintf("%x", hash.Sum(nil))
    return checksum, nil
}

// 文件 Sha1
func Sha1(filename string) (string, error) {
    openfile, err := os.Open(filename)
    if err != nil {
        return "", err
    }
    defer openfile.Close()

    return Sha1WithOsOpen(openfile)
}

// 文件 Sha1
func Sha1WithOsOpen(openfile *os.File) (string, error) {
    hash := sha1.New()
    _, err := io.Copy(hash, openfile)
    if nil != err {
        return "", err
    }

    sum := hash.Sum(nil)

    return fmt.Sprintf("%x", sum), nil
}

// 大文件 Sha1
func Sha1ForBig(filename string) (string, error) {
    if info, err := os.Stat(filename); err != nil {
        return "", err
    } else if info.IsDir() {
        return "", errors.New("不是文件无法计算")
    }

    openfile, err := os.Open(filename)
    if err != nil {
        return "", err
    }
    defer openfile.Close()

    return Sha1ForBigWithOsOpen(openfile)
}

// 大文件 Sha1
func Sha1ForBigWithOsOpen(openfile *os.File) (string, error) {
    const bufferSize = 65536

    hash := sha1.New()
    for buf, reader := make([]byte, bufferSize), bufio.NewReader(openfile); ; {
        n, err := reader.Read(buf)
        if err != nil {
            if err == io.EOF {
                break
            }
            return "", err
        }

        hash.Write(buf[:n])
    }

    checksum := fmt.Sprintf("%x", hash.Sum(nil))
    return checksum, nil
}
