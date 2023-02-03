package key

import (
    "fmt"
    "io/ioutil"

    cryptobin_bencode "github.com/deatil/go-cryptobin/bencode"
)

func ShowTorrent() {
    // ParseTorrent("./runtime/key/torrent/archlinux-2011.08.19-netinstall-i686.iso.torrent")
    ParseTorrent("./runtime/key/torrent/continuum.torrent")
}

func loadFile(name string) []byte {
    data, _ := ioutil.ReadFile(name)

    return data
}

func writeFile(filename string, data []byte) error {
    return ioutil.WriteFile(filename, data, 0644)
}

func ParseTorrent(filename string) {
    data := loadFile(filename)

    var list cryptobin_bencode.Data
    err := cryptobin_bencode.Unmarshal(data, &list)

    fmt.Println("===== Torrent =====")
    fmt.Println(fmt.Sprintf("Torrent err: %#v", err))

    fmt.Println("===== Torrent Keys =====")
    fmt.Println(fmt.Sprintf("keys: %#v", list.GetKeys()))

    fmt.Println("===== Torrent Data =====")
    fmt.Println(fmt.Sprintf("announce: %s", list["announce"]))
    fmt.Println(fmt.Sprintf("comment: %s", list["comment"]))
    fmt.Println(fmt.Sprintf("created by: %s", list["created by"]))
    fmt.Println(fmt.Sprintf("creation date: %s", list.GetCreationDateTime()))
    // fmt.Println(fmt.Sprintf("creation date: %s", list["creation date"]))
    // fmt.Println(fmt.Sprintf("announce-list: %#v", list["announce-list"]))
    // fmt.Println(fmt.Sprintf("url-list: %#v", list["url-list"]))
    // fmt.Println(fmt.Sprintf("info date: %s", list["info"]))
    fmt.Println(fmt.Sprintf("encoding: %s", list["encoding"]))
    fmt.Println(fmt.Sprintf("publisher: %s", list["publisher"]))
    fmt.Println(fmt.Sprintf("publisher-url: %s", list["publisher-url"]))

    fmt.Println("===== Torrent Info Keys =====")
    fmt.Println(fmt.Sprintf("Info keys: %#v", list.GetInfoKeys()))
    fmt.Println(fmt.Sprintf("Info name: %s", list.GetInfoItem("name")))

    /*
    // 更改后保存到文件
    list = list.SetAnnounce("http://baidu.com/abcde")
    newData, _ := cryptobin_bencode.Marshal(list)
    writeFile("./runtime/key/torrent/continuum-new.torrent", newData)
    */


    var list2 cryptobin_bencode.SingleTorrent
    err2 := cryptobin_bencode.Unmarshal(data, &list2)

    fmt.Println("===== Torrent2 =====")
    fmt.Println(fmt.Sprintf("Torrent err: %#v", err2))

    fmt.Println("===== Torrent2 Data =====")
    fmt.Println(fmt.Sprintf("announce: %s", list2.Announce))
    fmt.Println(fmt.Sprintf("creation date: %s", list2.GetCreationDateTime()))
    fmt.Println(fmt.Sprintf("info hash: %s", list2.GetInfoHashString()))
    fmt.Println(fmt.Sprintf("AnnounceList: %#v", list2.GetAnnounceList()))

}
