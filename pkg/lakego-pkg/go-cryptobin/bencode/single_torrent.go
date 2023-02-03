package bencode

import (
    "time"
    "crypto/sha1"
    "encoding/hex"
)

// 单文件
// 版本为通用类，非通用类需要直接用 map 获取数据或者生成数据
type SingleTorrent struct {
    // `bencode:""`
    // tracker服务器的URL 字符串
    Announce     string     `bencode:"announce"`
    // 备用tracker服务器列表 列表
    // 发现 announce-list 后面跟了两个l(ll) announce-listll
    AnnounceList [][]string `bencode:"announce-list,omitempty"`
    // 种子的创建时间 整数
    CreatDate    int64      `bencode:"creation date"`
    // 备注 字符串
    Comment      string     `bencode:"comment"`
    // 创建者 字符串
    CreatedBy    string     `bencode:"created by"`
    // 详情
    Info         SingleInfo `bencode:"info"`
    // 包含一系列ip和相应端口的列表，是用于连接DHT初始node
    Nodes        [][]any    `bencode:"nodes,omitempty"`
    // 文件的默认编码
    Encoding     string     `bencode:"encoding,omitempty"`
    // 备注的utf-8编码
    CommentUtf8  string     `bencode:"comment.utf-8,omitempty"`
}

// 获取备用节点
func (this SingleTorrent) GetAnnounceList() []string {
    announceList := []string{}

    for _, v := range this.AnnounceList {
        announceList = append(announceList, v...)
    }

    return announceList
}

// 获取格式化后的创建时间
func (this SingleTorrent) GetCreationDateTime(tz ...string) time.Time {
    timezone := "Local"
    if len(tz) > 0 {
        timezone = tz[0]
    }

    loc, _ := time.LoadLocation(timezone)

    return time.Unix(this.CreatDate, 0).In(loc)
}

// 设置创建时间
func (this SingleTorrent) SetCreationDateTime(t time.Time) SingleTorrent {
    this.CreatDate = t.Unix()

    return this
}

// 生成 info hash
func (this SingleTorrent) GetInfoHash() ([20]byte, error) {
    data, err := Marshal(this.Info)
    if err != nil {
        return [20]byte{}, err
    }

    // info hash，在与跟踪器和对等设备对话时，它唯一地标识文件
    h := sha1.Sum(data)
    return h, nil
}

// 生成 info hash 字符
func (this SingleTorrent) GetInfoHashString() string {
    sum, err := this.GetInfoHash()
    if err != nil {
        return ""
    }

    return hex.EncodeToString(sum[:])
}

// 单文件信息
type SingleInfo struct {
    Pieces      string `bencode:"pieces"`
    PieceLength int    `bencode:"piece length"`
    Length      int    `bencode:"length"`

    Name        string `bencode:"name"`
    NameUtf8    string `bencode:"name.utf-8,omitempty"`

    // 文件发布者
    Publisher     string `bencode:"publisher,omitempty"`
    PublisherUtf8 string `bencode:"publisher.utf-8,omitempty"`

    // 文件发布者的网址
    PublisherUrl     string `bencode:"publisher-url,omitempty"`
    PublisherUrlUtf8 string `bencode:"publisher-url.utf-8,omitempty"`

    MD5Sum           string `bencode:"md5sum,omitempty"`
    Private          bool   `bencode:"private,omitempty"`
}

// 每个分片的 SHA-1 hash 长度是20 把他们从Pieces中切出来
func (this SingleInfo) GetPieceHashes() ([][20]byte, error) {
    return splitPieceHashes(this.Pieces)
}
