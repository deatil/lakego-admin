package register

/**
 * 初始化
 */
func NewManager() *Manager {
    return &Manager{}
}

/**
 * 初始化
 */
func NewManagerWithPrefix(prefix string) *Manager {
    return &Manager{
        prefix: prefix,
    }
}

/**
 * 注册管理器
 */
type Manager struct {
    prefix string
}

/**
 * 设置前缀
 */
func (m *Manager) WithPrefix(prefix string) *Manager {
    m.prefix = prefix

    return m
}

/**
 * 获取前缀
 */
func (m *Manager) GetPrefix(prefix string) string {
    return m.prefix
}

/**
 * 注册驱动
 */
func (m *Manager) Register(name string, f func(map[string]interface{}) interface{}) {
    name = m.prefix + name

    New().With(name, func(conf map[string]interface{}) interface{} {
        return f(conf)
    })
}

/**
 * 批量注册驱动
 */
func (m *Manager) RegisterMany(drivers map[string]func(map[string]interface{}) interface{}) {
    for name, f := range drivers {
        m.Register(name, f)
    }
}

/**
 * 获取已注册驱动
 */
func (m *Manager) GetRegister(name string, conf map[string]interface{}, once ...bool) interface{} {
    name = m.prefix + name

    var data interface{}
    reg := New()
    if len(once) > 0 && once[0] {
        data = reg.GetOnce(name, conf)
    } else {
        data = reg.Get(name, conf)
    }

    if data != nil {
        return data
    }

    return nil
}
