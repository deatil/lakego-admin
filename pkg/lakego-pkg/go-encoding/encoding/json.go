package encoding

import (
    "encoding/json"
)

// Json 编码
func JsonEncode(src interface{}) string {
    data, _ := json.Marshal(src)

    return string(data)
}

// Json 解码
func JsonDecode(data string, dst interface{}) error {
    return json.Unmarshal([]byte(data), dst)
}
