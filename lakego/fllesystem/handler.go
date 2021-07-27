package handler

import(
    "lakego-admin/lakego/fllesystem/intrface"
)

type Handler struct {
    filesystem intrface.Fllesystem
    path string
}

func (hand *Handler) IsDir() bool {
    return hand.GetType() == "dir"
}

func (hand *Handler) IsFile() bool {
    return hand.GetType() == "file"
}

func (hand *Handler) GetType() string {
    metadata := hand.filesystem.GetMetadata(hand.path)

    if metadata == nil {
        return "dir"
    }

    return metadata["type"]
}

func (hand *Handler) SetFilesystem(filesystem intrface.Fllesystem) *interface{} {
    hand.filesystem = filesystem

    return hand
}

func (hand *Handler) GetFilesystem() intrface.Fllesystem {
    return hand.filesystem
}

func (hand *Handler) SetPath(path string) *interface{} {
    hand.path = path

    return hand
}

func (hand *Handler) GetPath() string {
    return hand.path
}
