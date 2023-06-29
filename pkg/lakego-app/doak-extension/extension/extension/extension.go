package extension

import (
    "encoding/json"

    iapp "github.com/deatil/lakego-doak/lakego/app/interfaces"
)

// 作者信息
type Author struct {
    // 名称
    Name string `json:"name"`

    // 邮箱
    Email string `json:"email"`

    // 主页
    Homepage string `json:"homepage"`
}

// 扩展实现
type Extension struct {
    // 名称, 比如 lakego.log-viewer
    Name string `json:"name"`

    // 扩展名称
    Title string `json:"title"`

    // 扩展描述
    Description string `json:"description"`

    // 扩展关键字
    Keywords []string `json:"keywords"`

    // 扩展主页
    Homepage string `json:"homepage"`

    // 作者
    Authors []Author `json:"authors"`

    // 版本号
    Version string `json:"version"`

    // 适配系统版本
    Adaptation string `json:"adaptation"`

    // 依赖扩展[选填]
    // map[string]string{'lakego.log-viewer' => '1.0.*'}
    Require map[string]string `json:"require"`

    // 安装后
    Install func() error `json:"-"`

    // 卸载后
    Uninstall func() error `json:"-"`

    // 更新后
    Upgrade func() error `json:"-"`

    // 启用后
    Enable func() error `json:"-"`

    // 禁用后
    Disable func() error `json:"-"`

    // 安装启用后运行
    Start func(iapp.App) error `json:"-"`
}

func (this Extension) ToJSON() []byte {
    data, err := json.Marshal(this)
    if err != nil {
        return nil
    }

    return data
}
