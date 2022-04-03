package register

/**
 * 初始化
 */
func NewManager() *Manager {
    return &Manager{
        prefix: "",
    }
}

/**
 * 初始化
 */
func NewManagerWithPrefix(prefix string) *Manager {
    return &Manager{
        prefix: prefix,
    }
}

type (
    // 配置 Map
    ManagerConfigMap = map[string]interface{}

    // 注册的方法
    ManagerRegisterFunc = func(ManagerConfigMap) interface{}
)

/**
 * 注册管理器
 *
 * @create 2021-9-6
 * @author deatil
 */
type Manager struct {
    prefix string
}

/**
 * 设置前缀
 */
func (this *Manager) WithPrefix(prefix string) *Manager {
    this.prefix = prefix

    return this
}

/**
 * 获取前缀
 */
func (this *Manager) GetPrefix(prefix string) string {
    return this.prefix
}

/**
 * 注册驱动
 */
func (this *Manager) Register(name string, f ManagerRegisterFunc) {
    name = this.FormatName(name)

    New().With(name, func(conf ManagerConfigMap) interface{} {
        return f(conf)
    })
}

/**
 * 批量注册驱动
 */
func (this *Manager) RegisterMany(drivers map[string]ManagerRegisterFunc) {
    for name, f := range drivers {
        this.Register(name, f)
    }
}

/**
 * 获取已注册驱动
 */
func (this *Manager) GetRegister(name string, conf ManagerConfigMap, once ...bool) interface{} {
    name = this.FormatName(name)

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

/**
 * 格式化名称
 */
func (this *Manager) FormatName(name string) string {
    name = this.prefix + "::" + name

    return name
}
