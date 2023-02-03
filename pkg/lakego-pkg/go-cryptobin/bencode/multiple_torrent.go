package bencode

import (
    "time"
    "crypto/sha1"
    "encoding/hex"
)

// 多文件 包含5:files
// 版本为通用类，非通用类需要直接用 map 获取数据或者生成数据
type MultipleTorrent struct {
    // `bencode:""`
    // tracker服务器的URL 字符串
    Announce     string          `bencode:"announce"`
    // 备用tracker服务器列表 列表
    // 发现 announce-list 后面跟了两个l(ll) announce-listll
    AnnounceList [][]string      `bencode:"announce-list,omitempty"`
    // 种子的创建时间 整数
    CreatDate    int64           `bencode:"creation date"`
    // 备注 字符串
    Comment      string          `bencode:"comment"`
    // 创建者 字符串
    CreatedBy    string          `bencode:"created by"`
    // 详情
    Info         MultipleInfo    `bencode:"info"`
    // 包含一系列ip和相应端口的列表，是用于连接DHT初始node
    Nodes        [][]any         `bencode:"nodes,omitempty"`
    // 文件的默认编码
    Encoding     string          `bencode:"encoding,omitempty"`
    // 备注的utf-8编码
    CommentUtf8  string          `bencode:"comment.utf-8,omitempty"`
}

// 获取备用节点
func (this MultipleTorrent) GetAnnounceList() []string {
    announceList := []string{}

    for _, v := range this.AnnounceList {
        announceList = append(announceList, v...)
    }

    return announceList
}

// 获取格式化后的创建时间
func (this MultipleTorrent) GetCreationDateTime(tz ...string) time.Time {
    timezone := "Local"
    if len(tz) > 0 {
        timezone = tz[0]
    }

    loc, _ := time.LoadLocation(timezone)

    return time.Unix(this.CreatDate, 0).In(loc)
}

// 设置创建时间
func (this MultipleTorrent) SetCreationDateTime(t time.Time) MultipleTorrent {
    this.CreatDate = t.Unix()

    return this
}

// 生成 info hash
func (this MultipleTorrent) GetInfoHash() ([20]byte, error) {
    data, err := Marshal(this.Info)
    if err != nil {
        return [20]byte{}, err
    }

    // info hash，在与跟踪器和对等设备对话时，它唯一地标识文件
    h := sha1.Sum(data)
    return h, nil
}

// 生成 info hash 字符
func (this MultipleTorrent) GetInfoHashString() string {
    sum, err := this.GetInfoHash()
    if err != nil {
        return ""
    }

    return hex.EncodeToString(sum[:])
}

// 返回数据用的
type FileInfo struct {
    Path   string
    Length int
}

// 文件信息
type MultipleInfoFile struct {
    // 文件长度 单位字节 整数
    Length   int      `bencode:"length"`
    // 文件的路径和名字 列表
    Path     []string `bencode:"path"`
    // path.utf-8：文件名的UTF-8编码
    PathUtf8 string   `bencode:"path.utf-8,omitempty"`
}

// 多文件信息
type MultipleInfo struct {
    // 每个块的20个字节的SHA1 Hash的值(二进制格式)
    Pieces      string             `bencode:"pieces"`
    // 每个块的大小，单位字节 整数
    PieceLength int                `bencode:"piece length"`
    // 文件长度 整数
    Length      int                `bencode:"length,omitempty"`

    // 目录名 字符串
    Name        string             `bencode:"name"`
    // 目录名编码
    NameUtf8    string             `bencode:"name.utf-8,omitempty"`

    // 文件信息
    Files       []MultipleInfoFile `bencode:"files"`
}

// 每个分片的 SHA-1 hash 长度是20 把他们从Pieces中切出来
func (this MultipleInfo) GetPieceHashes() ([][20]byte, error) {
    return splitPieceHashes(this.Pieces)
}

// 返回文件数据列表
func (this MultipleInfo) GetFileList() []FileInfo {
    // 构建 fileInfo 列表
    var fileInfo []FileInfo

    for _, v := range this.Files {
        path := ""

        for _, p := range v.Path {
            path += "/" + p
        }

        fileInfo = append(fileInfo, FileInfo{
            Path:   path,
            Length: v.Length,
        })
    }

    return fileInfo
}
