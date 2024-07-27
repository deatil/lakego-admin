package event

// 接口
type ISubscribe interface {
	Subscribe(*Events)
}

// 接口
type ISubscribePrefix interface {
	EventPrefix() string
}
