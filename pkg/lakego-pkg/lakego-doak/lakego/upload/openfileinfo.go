package upload

import (
    "io"
    "os"
    "fmt"
    "path"
    "bufio"
    "regexp"
    "strings"
    "net/http"
    "crypto/md5"
    "crypto/sha1"
)

/**
 * 文件信息
 *
 * @create 2021-9-29
 * @author deatil
 */
type OpenFileinfo struct {
    // 文件
    fileName string

    // 文件流
    file *os.File

    // 文件类型
    filetypes map[string]string
}

// 文件信息
func NewOpenFileinfo() *OpenFileinfo {
    return &OpenFileinfo{
        filetypes: map[string]string{},
    }
}

// 设置文件流
func (this *OpenFileinfo) WithFileName(fileName string) *OpenFileinfo {
    this.fileName = fileName

    // 添加文件流
    file, _ := os.Open(fileName)
    this.file = file

    return this
}

// 获取文件流
func (this *OpenFileinfo) GetFileName() string {
    return this.fileName
}

// 设置文件流
func (this *OpenFileinfo) WithFile(file *os.File) *OpenFileinfo {
    this.file = file

    return this
}

// 获取文件流
func (this *OpenFileinfo) GetFile() *os.File {
    return this.file
}

// 关闭文件流
func (this *OpenFileinfo) CloseFile() {
    defer this.file.Close()
}

// 设置文件类型
func (this *OpenFileinfo) WithFiletypes(filetypes map[string]string) *OpenFileinfo {
    this.filetypes = filetypes

    return this
}

// 获取文件类型
func (this *OpenFileinfo) GetFiletypes() map[string]string {
    return this.filetypes
}

// 字符
func (this *OpenFileinfo) String() string {
    return this.GetOriginalFilename()
}

// mime
func (this *OpenFileinfo) GetMimeType() string {
    // 头部字节
    buffer := make([]byte, 32)
    if _, err := this.file.Read(buffer); err != nil {
        return ""
    }

    mimetype := http.DetectContentType(buffer)

    return mimetype
}

// 后缀
func (this *OpenFileinfo) GetExtension() string {
    f, _ := this.file.Stat()
    name := f.Name()

    return strings.TrimPrefix(path.Ext(name), ".")
}

// 大小
func (this *OpenFileinfo) GetSize() int64 {
    f, _ := this.file.Stat()

    return f.Size()
}

// 原始名称
func (this *OpenFileinfo) GetOriginalName() string {
    f, _ := this.file.Stat()
    name := f.Name()

    return strings.TrimSuffix(name, "." + this.GetExtension())
}

// 原始文件名
func (this *OpenFileinfo) GetOriginalFilename() string {
    f, _ := this.file.Stat()

    return f.Name()
}

// MD5 摘要
func (this *OpenFileinfo) GetMd5() string {
    const bufferSize = 65536

    hash := md5.New()
    for buf, reader := make([]byte, bufferSize), bufio.NewReader(this.file); ; {
        n, err := reader.Read(buf)
        if err != nil {
            if err == io.EOF {
                break
            }
            return ""
        }

        hash.Write(buf[:n])
    }

    checksum := fmt.Sprintf("%x", hash.Sum(nil))

    return checksum
}

// sha1 摘要
func (this *OpenFileinfo) GetSha1() string {
    const bufferSize = 65536

    hash := sha1.New()
    for buf, reader := make([]byte, bufferSize), bufio.NewReader(this.file); ; {
        n, err := reader.Read(buf)
        if err != nil {
            if err == io.EOF {
                break
            }
            return ""
        }

        hash.Write(buf[:n])
    }

    checksum := fmt.Sprintf("%x", hash.Sum(nil))

    return checksum
}

// 文件大类
func (this *OpenFileinfo) GetFileType() string {
    filetypes := this.filetypes

    extension := this.GetExtension()

    filetype := "other"

    for typer, pattern := range filetypes {
        if match, _ := regexp.MatchString(pattern, extension); match {
            filetype = typer
            break
        }
    }

    return filetype
}

