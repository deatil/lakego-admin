package gmq

import (
    "errors"
)

// 内容
type Payload struct {
    // 主题
    Topic string

    // 内容
    Value any
}

// 处理业务
type Handler func(value any)

// 消息中间件
type GMQ struct {
    // 载荷
    payload chan Payload

    // 退出
    quit chan bool

    // 列表
    handles map[string][]Handler

    // 是否运行
    running bool
}

// 新建GMQ
func NewGMQ() *GMQ {
    return &GMQ{
        payload: make(chan Payload),
        quit:    make(chan bool),
        handles: make(map[string][]Handler),
    }
}

// 构造函数
func New() *GMQ {
    return NewGMQ()
}

// 发布
func (this *GMQ) Publish(topic string, data any) error {
    if !this.running {
        return errors.New("GMQ is not running yet")
    }

    this.payload <- Payload{topic, data}

    return nil
}

// 订阅
func (this *GMQ) Subscribe(topic string, handler Handler) {
    if nil == this.handles {
        this.handles = make(map[string][]Handler)
    }

    if nil == this.handles[topic] {
        this.handles[topic] = []Handler{handler}
    } else {
        this.handles[topic] = append(this.handles[topic], handler)
    }
}

// 处理业务
func (this *GMQ) handle(value any, handlers []Handler) {
    for _, handler := range handlers {
        handler(value)
    }
}

// 运行
func (this *GMQ) Run() {
    if this.running {
        return
    }

    // 设置为运行
    this.running = true

    for {
        select {
            case v := <-this.payload:
                if nil != this.handles[v.Topic] {
                    go this.handle(v.Value, this.handles[v.Topic])
                }
            case v := <-this.quit:
                if v {
                    close(this.payload)
                    close(this.quit)
                    break
                }
        }
    }
}

// 关闭
func (this *GMQ) Close()  {
    this.quit <- true
}
