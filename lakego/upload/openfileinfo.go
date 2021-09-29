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

// 文件信息
func NewOpenFileinfo() *OpenFileinfo {
    return &OpenFileinfo{
        filetypes: map[string]string{},
    }
}

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

// 设置文件流
func (fileinfo *OpenFileinfo) WithFileName(fileName string) *OpenFileinfo {
    fileinfo.fileName = fileName

    // 添加文件流
    file, _ := os.Open(fileName)
    fileinfo.file = file

    return fileinfo
}

// 获取文件流
func (fileinfo *OpenFileinfo) GetFileName() string {
    return fileinfo.fileName
}

// 设置文件流
func (fileinfo *OpenFileinfo) WithFile(file *os.File) *OpenFileinfo {
    fileinfo.file = file

    return fileinfo
}

// 获取文件流
func (fileinfo *OpenFileinfo) GetFile() *os.File {
    return fileinfo.file
}

// 关闭文件流
func (fileinfo *OpenFileinfo) CloseFile() {
    defer fileinfo.file.Close()
}

// 设置文件类型
func (fileinfo *OpenFileinfo) WithFiletypes(filetypes map[string]string) *OpenFileinfo {
    fileinfo.filetypes = filetypes

    return fileinfo
}

// 获取文件类型
func (fileinfo *OpenFileinfo) GetFiletypes() map[string]string {
    return fileinfo.filetypes
}

// 字符
func (fileinfo *OpenFileinfo) String() string {
    return fileinfo.GetOriginalFilename()
}

// mime
func (fileinfo *OpenFileinfo) GetMimeType() string {
    // 头部字节
    buffer := make([]byte, 32)
    if _, err := fileinfo.file.Read(buffer); err != nil {
        return ""
    }

    mimetype := http.DetectContentType(buffer)

    return mimetype
}

// 后缀
func (fileinfo *OpenFileinfo) GetExtension() string {
    f, _ := fileinfo.file.Stat()
    name := f.Name()

    return strings.TrimPrefix(path.Ext(name), ".")
}

// 大小
func (fileinfo *OpenFileinfo) GetSize() int64 {
    f, _ := fileinfo.file.Stat()

    return f.Size()
}

// 原始名称
func (fileinfo *OpenFileinfo) GetOriginalName() string {
    f, _ := fileinfo.file.Stat()
    name := f.Name()

    return strings.TrimSuffix(name, "." + fileinfo.GetExtension())
}

// 原始文件名
func (fileinfo *OpenFileinfo) GetOriginalFilename() string {
    f, _ := fileinfo.file.Stat()

    return f.Name()
}

// MD5 摘要
func (fileinfo *OpenFileinfo) GetMd5() string {
    const bufferSize = 65536

    hash := md5.New()
    for buf, reader := make([]byte, bufferSize), bufio.NewReader(fileinfo.file); ; {
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
func (fileinfo *OpenFileinfo) GetSha1() string {
    const bufferSize = 65536

    hash := sha1.New()
    for buf, reader := make([]byte, bufferSize), bufio.NewReader(fileinfo.file); ; {
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
func (fileinfo *OpenFileinfo) GetFileType() string {
    filetypes := fileinfo.filetypes

    extension := fileinfo.GetExtension()

    filetype := "other"

    for typer, pattern := range filetypes {
        if match, _ := regexp.MatchString(pattern, extension); match {
            filetype = typer
            break
        }
    }

    return filetype
}

