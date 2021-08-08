package fllesystem

import(
    "lakego-admin/lakego/fllesystem/interfaces"
)

type Handler struct {
    filesystem interfaces.Fllesystem
    path string
}

// 是否为文件夹
func (hand *Handler) IsDir() bool {
    return hand.GetType() == "dir"
}

// 是否为文件
func (hand *Handler) IsFile() bool {
    return hand.GetType() == "file"
}

// 类型
func (hand *Handler) GetType() string {
    metadata := hand.filesystem.GetMetadata(hand.path)

    if metadata == nil {
        return "dir"
    }

    return metadata["type"].(string)
}

// 设置文件系统
func (hand *Handler) SetFilesystem(filesystem interfaces.Fllesystem) interface{} {
    hand.filesystem = filesystem

    return hand
}

// 获取文件系统
func (hand *Handler) GetFilesystem() interfaces.Fllesystem {
    return hand.filesystem
}

// 设置目录
func (hand *Handler) SetPath(path string) interface{} {
    hand.path = path

    return hand
}

// 获取目录
func (hand *Handler) GetPath() string {
    return hand.path
}
