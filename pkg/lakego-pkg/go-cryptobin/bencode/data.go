package bencode

import (
    "time"
    "encoding/json"
)

// 接收解析后的数据
type Data map[string]any

// 已有的字段
func (this Data) GetKeys() []string {
    var keys []string

    for key, _ := range this {
        keys = append(keys, key)
    }

    return keys
}

// 获取单个数据
func (this Data) GetItem(key string) any {
    return this[key]
}

// 获取单个数据字符
func (this Data) GetItemString(key string) string {
    item := this.GetItem(key)

    if data, ok := item.(string); ok {
        return data
    }

    return ""
}

// 获取单个数据 int64
func (this Data) GetItemInt64(key string) int64 {
    item := this.GetItem(key)

    if date, ok := item.(int64); ok {
        return date
    }

    return 0
}

// 获取单个数据 Map
func (this Data) GetItemMap(key string) map[string]any {
    item := this.GetItem(key)

    if data, ok := item.(map[string]any); ok {
        return data
    }

    return map[string]any{}
}

// 获取 Announce
func (this Data) GetAnnounce() string {
    return this.GetItemString("announce")
}

// 获取 Comment
func (this Data) GetComment() string {
    return this.GetItemString("comment")
}

// 获取 CreatedBy
func (this Data) GetCreatedBy() string {
    return this.GetItemString("created by")
}

// 获取创建时间
func (this Data) GetCreationDate() int64 {
    return this.GetItemInt64("creation date")
}

// 获取格式化后的创建时间
func (this Data) GetCreationDateTime(tz ...string) time.Time {
    timezone := "Local"
    if len(tz) > 0 {
        timezone = tz[0]
    }

    loc, _ := time.LoadLocation(timezone)

    return time.Unix(this.GetCreationDate(), 0).In(loc)
}

// 获取 Info
func (this Data) GetInfo() map[string]any {
    return this.GetItemMap("info")
}

// Info 已有的字段
func (this Data) GetInfoKeys() []string {
    var keys []string

    for key, _ := range this.GetInfo() {
        keys = append(keys, key)
    }

    return keys
}

// 获取 Info
func (this Data) GetInfoItem(key string) any {
    data := this.GetInfo()

    return data[key]
}

// 返回 map 数据
func (this Data) ToArray() map[string]any {
    return this
}

// 返回 json 字符数据
func (this Data) ToJSON() string {
    data, _ := json.Marshal(this.ToArray())

    return string(data)
}

// 返回 Info 数据
func (this Data) ToInfoArray() map[string]any {
    return this.GetInfo()
}

// 返回 Info 的 json 字符数据
func (this Data) ToInfoJSON() string {
    data, _ := json.Marshal(this.GetInfo())

    return string(data)
}

// 返回字符
func (this Data) String() string {
    return this.ToJSON()
}

// ==================

// 设置数据
func (this Data) SetItem(key string, data any) Data {
    this[key] = data

    return this
}

// 设置 Announce
func (this Data) SetAnnounce(data string) Data {
    return this.SetItem("announce", data)
}

// 设置 Comment
func (this Data) SetComment(data string) Data {
    return this.SetItem("comment", data)
}

// 设置 CreatedBy
func (this Data) SetCreatedBy(data string) Data {
    return this.SetItem("created by", data)
}

// 设置创建时间
func (this Data) SetCreationDate(data int64) Data {
    return this.SetItem("creation date", data)
}

// 设置创建时间
func (this Data) SetCreationDateTime(t time.Time) Data {
    return this.SetCreationDate(t.Unix())
}

// 设置 Info
func (this Data) SetInfo(data map[string]any) Data {
    return this.SetItem("info", data)
}
