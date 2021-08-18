package upload

import (
    "os"
    "path"
    "regexp"
    "strings"
    "net/http"

    "lakego-admin/lakego/support/file"
)

/**
 * 文件信息
 *
 * @create 2021-8-15
 * @author deatil
 */
type Fileinfo struct {
    // 文件
    file *os.File

    // 文件类型
    filetypes map[string]string
}

func NewFileinfo() *Fileinfo {
    return &Fileinfo{
        filetypes: map[string]string{},
    }
}

// 设置文件
func (fileinfo *Fileinfo) WithFilename(filename string) *Fileinfo {
    fileinfo.file, _ = os.Open(filename)

    return fileinfo
}

// 设置文件流
func (fileinfo *Fileinfo) WithFile(file *os.File) *Fileinfo {
    fileinfo.file = file

    return fileinfo
}

// 设置文件流
func (fileinfo *Fileinfo) GetFile() *os.File {
    return fileinfo.file
}

// 设置文件类型
func (fileinfo *Fileinfo) WithFiletypes(filetypes map[string]string) *Fileinfo {
    fileinfo.filetypes = filetypes

    return fileinfo
}

// 创建文件
func (fileinfo *Fileinfo) EnsureDir(path string) bool {
    err := file.EnsureDir(path)
    if err != nil {
        return false
    }

    return true
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
    s, err := fileinfo.file.Stat()
    if err != nil {
        return ""
    }

    name := s.Name()

    return strings.TrimPrefix(path.Ext(name), ".")
}

// 大小
func (fileinfo *Fileinfo) GetSize() int64 {
    s, err := fileinfo.file.Stat()
    if err != nil {
        return 0
    }

    return s.Size()
}

// 原始名称
func (fileinfo *Fileinfo) GetOriginalName() string {
    s, err := fileinfo.file.Stat()
    if err != nil {
        return ""
    }

    name := s.Name()

    return strings.TrimSuffix(name, "." + fileinfo.GetExtension())
}

// 原始文件名
func (fileinfo *Fileinfo) GetOriginalFilename() string {
    s, err := fileinfo.file.Stat()
    if err != nil {
        return ""
    }

    return s.Name()
}

// MD5 摘要
func (fileinfo *Fileinfo) GetMd5() string {
    str, err := file.Md5ForBigWithStream(fileinfo.file)
    if err != nil {
        return ""
    }

    return str
}

// sha1 摘要
func (fileinfo *Fileinfo) GetSha1() string {
    str, err := file.Sha1ForBigWithStream(fileinfo.file)
    if err != nil {
        return ""
    }

    return str
}

// 关闭文件流
func (fileinfo *Fileinfo) Close() {
    defer fileinfo.file.Close()
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

