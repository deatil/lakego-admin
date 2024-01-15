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

// 文件信息
func NewFileinfo() *Fileinfo {
    return &Fileinfo{
        filetypes: map[string]string{},
    }
}

// 设置文件流
func (this *Fileinfo) WithFile(file *multipart.FileHeader) *Fileinfo {
    this.fileHeader = file

    openfile, err := file.Open()
    if err != nil {
        panic("打开上传文件失败")
    }

    this.file = openfile

    return this
}

// 关闭文件流
func (this *Fileinfo) CloseFile() {
    defer this.file.Close()
}

// 获取文件
func (this *Fileinfo) GetFileHeader() *multipart.FileHeader {
    return this.fileHeader
}

// 获取文件流
func (this *Fileinfo) GetFile() multipart.File {
    return this.file
}

// 设置文件类型
func (this *Fileinfo) WithFiletypes(filetypes map[string]string) *Fileinfo {
    this.filetypes = filetypes

    return this
}

// 获取文件类型
func (this *Fileinfo) GetFiletypes() map[string]string {
    return this.filetypes
}

// mime
func (this *Fileinfo) GetMimeType() string {
    // 头部字节
    buffer := make([]byte, 32)
    if _, err := this.file.Read(buffer); err != nil {
        return ""
    }

    mimetype := http.DetectContentType(buffer)

    return mimetype
}

// 后缀
func (this *Fileinfo) GetExtension() string {
    name := this.fileHeader.Filename

    return strings.TrimPrefix(path.Ext(name), ".")
}

// 大小
func (this *Fileinfo) GetSize() int64 {
    return this.fileHeader.Size
}

// 原始名称
func (this *Fileinfo) GetOriginalName() string {
    name := this.fileHeader.Filename

    return strings.TrimSuffix(name, "." + this.GetExtension())
}

// 原始文件名
func (this *Fileinfo) GetOriginalFilename() string {
    return this.fileHeader.Filename
}

// MD5 摘要
func (this *Fileinfo) GetMd5() string {
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
func (this *Fileinfo) GetSha1() string {
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
func (this *Fileinfo) GetFileType() string {
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

