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

    var iface any
    err := cryptobin_bencode.Unmarshal(data, &iface)

    fmt.Println("===== Torrent =====")
    fmt.Printf("Torrent err: %#v", err)
    fmt.Println("")

    fmt.Println("Data Item: ")
    if list, ok := iface.(map[string]any); ok {
        fmt.Println(fmt.Sprintf("announce: %s", list["announce"]))
        fmt.Println(fmt.Sprintf("comment: %s", list["comment"]))
        fmt.Println(fmt.Sprintf("created by: %s", list["created by"]))
        fmt.Println(fmt.Sprintf("creation date: %s", list["creation date"]))
        // fmt.Println(fmt.Sprintf("announce-list: %#v", list["announce-list"]))
        // fmt.Println(fmt.Sprintf("url-list: %#v", list["url-list"]))
        // fmt.Println(fmt.Sprintf("info date: %s", list["info"]))
        fmt.Println(fmt.Sprintf("encoding: %s", list["encoding"]))
        fmt.Println(fmt.Sprintf("publisher: %s", list["publisher"]))
        fmt.Println(fmt.Sprintf("publisher-url: %s", list["publisher-url"]))
    }

}
