package events

// 默认排序
const DefaultSort = 1;

/**
 * Events
 *
 * @create 2024-7-26
 * @author deatil
 */
type Events struct {
    // 动作事件
    actionHandle *Action

    // 过滤事件
    filterHandle *Filter
}

// 构造函数
// New Events
func New() *Events {
    return &Events{
        actionHandle: NewAction(),
        filterHandle: NewFilter(),
    }
}

// 获取动作事件
func (this *Events) Action() *Action {
    return this.actionHandle
}

// 获取过滤事件
func (this *Events) Filter() *Filter {
    return this.filterHandle
}
