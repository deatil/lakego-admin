package file

import (
    "os"
    "io"
    "fmt"
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

    hash := md5.New()
    _, err = io.Copy(hash, openfile)
    if nil != err {
        return "", err
    }

    sum := hash.Sum(nil)

    return fmt.Sprintf("%x", sum), nil
}

// 大文件 Md5
func Md5WithBig(filename string) (string, error) {
    if info, err := os.Stat(filename); err != nil {
        return "", err
    } else if info.IsDir() {
        return "", nil
    }

    file, err := os.Open(filename)
    if err != nil {
        return "", err
    }
    defer file.Close()

    const bufferSize = 65536

    hash := md5.New()
    for buf, reader := make([]byte, bufferSize), bufio.NewReader(file); ; {
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

    hash := sha1.New()
    _, err = io.Copy(hash, openfile)
    if nil != err {
        return "", err
    }

    sum := hash.Sum(nil)

    return fmt.Sprintf("%x", sum), nil
}

// 大文件 Sha1
func Sha1WithBig(filename string) (string, error) {
    if info, err := os.Stat(filename); err != nil {
        return "", err
    } else if info.IsDir() {
        return "", nil
    }

    file, err := os.Open(filename)
    if err != nil {
        return "", err
    }
    defer file.Close()

    const bufferSize = 65536

    hash := sha1.New()
    for buf, reader := make([]byte, bufferSize), bufio.NewReader(file); ; {
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
