package upload

import (
    "io"
    "fmt"
    "path"
    "bufio"
    "regexp"
    "strings"
    "net/http"
    "crypto/md5"
    "crypto/sha1"
    "mime/multipart"
)

// 文件信息
func NewFileinfo() *Fileinfo {
    return &Fileinfo{
        filetypes: map[string]string{},
    }
}

/**
 * 文件信息
 *
 * @create 2021-8-15
 * @author deatil
 */
type Fileinfo struct {
    // 文件
    fileHeader *multipart.FileHeader

    // 文件流
    file multipart.File

    // 文件类型
    filetypes map[string]string
}

// 设置文件流
func (fileinfo *Fileinfo) WithFile(file *multipart.FileHeader) *Fileinfo {
    fileinfo.fileHeader = file

    openfile, err := file.Open()
    if err != nil {
        panic("打开上传文件失败")
    }

    fileinfo.file = openfile

    return fileinfo
}

// 关闭文件流
func (fileinfo *Fileinfo) CloseFile() {
    defer fileinfo.file.Close()
}

// 获取文件
func (fileinfo *Fileinfo) GetFileHeader() *multipart.FileHeader {
    return fileinfo.fileHeader
}

// 获取文件流
func (fileinfo *Fileinfo) GetFile() multipart.File {
    return fileinfo.file
}

// 设置文件类型
func (fileinfo *Fileinfo) WithFiletypes(filetypes map[string]string) *Fileinfo {
    fileinfo.filetypes = filetypes

    return fileinfo
}

// 获取文件类型
func (fileinfo *Fileinfo) GetFiletypes() map[string]string {
    return fileinfo.filetypes
}

// mime
func (fileinfo *Fileinfo) GetMimeType() string {
    // 头部字节
    buffer := make([]byte, 32)
    if _, err := fileinfo.file.Read(buffer); err != nil {
        return ""
    }

    mimetype := http.DetectContentType(buffer)

    return mimetype
}

// 后缀
func (fileinfo *Fileinfo) GetExtension() string {
    name := fileinfo.fileHeader.Filename

    return strings.TrimPrefix(path.Ext(name), ".")
}

// 大小
func (fileinfo *Fileinfo) GetSize() int64 {
    return fileinfo.fileHeader.Size
}

// 原始名称
func (fileinfo *Fileinfo) GetOriginalName() string {
    name := fileinfo.fileHeader.Filename

    return strings.TrimSuffix(name, "." + fileinfo.GetExtension())
}

// 原始文件名
func (fileinfo *Fileinfo) GetOriginalFilename() string {
    return fileinfo.fileHeader.Filename
}

// MD5 摘要
func (fileinfo *Fileinfo) GetMd5() string {
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
func (fileinfo *Fileinfo) GetSha1() string {
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
func (fileinfo *Fileinfo) GetFileType() string {
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

