### Torrent 文件解析使用说明
bencode 格式为 `Bt` 种子 `Torrent` 的自有格式


* 引用
~~~go
import "github.com/deatil/go-cryptobin/bencode"
~~~

* 解析文件数据
~~~go
// 读取文件获得的数据
var torrentData []byte

// 解析结果
var data map[string]any
// 解析结果，使用自带 map
// var data bencode.Data
// 解析结果，使用单文件结构体
// var data bencode.SingleTorrent
// 解析结果，使用多文件结构体
// var data bencode.MultipleTorrent

// 解析操作
err := bencode.Unmarshal(torrentData, &data)
~~~

* 生成文件数据
~~~go
// 解析结果
var data map[string]any
// 解析结果，使用自带 map
// var data bencode.Data
// 解析结果，使用单文件结构体
// var data bencode.SingleTorrent
// 解析结果，使用多文件结构体
// var data bencode.MultipleTorrent

// 数据结果
var torrentData []byte

// 生成操作
torrentData, err := bencode.Marshal(data)
~~~
