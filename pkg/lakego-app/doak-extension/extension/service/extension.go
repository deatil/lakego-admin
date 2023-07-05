package service

import (
    "fmt"
    "errors"

    "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-datebin/datebin"

    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/facade/config"

    admin_model "github.com/deatil/lakego-doak-admin/admin/model"

    "github.com/deatil/lakego-doak-extension/extension/model"
    "github.com/deatil/lakego-doak-extension/extension/version"
    "github.com/deatil/lakego-doak-extension/extension/extension"
)

/**
 * 扩展
 *
 * @create 2023-7-3
 * @author deatil
 */
type Extension struct {
    Ctx *router.Context
}

// 构造函数
func NewExtension() *Extension {
    return &Extension{}
}

// 构造函数
func NewExtensionWithCtx(ctx *router.Context) *Extension {
    return &Extension{ctx}
}

// 设置上下文
func (this *Extension) WithCtx(ctx *router.Context) *Extension {
    this.Ctx = ctx

    return this
}

// 本地扩展
func (this *Extension) Local() []map[string]any {
    exts := extension.GetManager().GetExtensions()

    extsMap := admin_model.FormatStructToArrayMap(exts)

    installExts := model.GetAllExtensions()

    installExts2 := make(map[string]map[string]any)
    for _, v := range installExts {
        installExts2[goch.ToString(v["name"])] = v
    }

    newExts := make([]map[string]any, 0)
    for _, ext := range extsMap {
        if installExt, ok := installExts2[goch.ToString(ext["name"])]; ok {
            ext["install"] = installExt

            infoVersion := goch.ToString(ext["version"])
            installVersion := goch.ToString(installExt["version"])

            err := version.VersionCheck(infoVersion, fmt.Sprintf("> %s", installVersion))
            if err == nil {
                ext["upgrade"] = 1
            } else {
                ext["upgrade"] = 0
            }
        } else {
            ext["install"] = map[string]any{}
            ext["upgrade"] = 0
        }

        newExts = append(newExts, ext)
    }

    return newExts
}

// 安装扩展
func (this *Extension) Inatll(name string) error {
    if name == "" {
        return errors.New("扩展不能为空")
    }

    extManager := extension.GetManager()

    info := extManager.GetExtension(name)
    if info.Name == "" {
        return errors.New("扩展不存在")
    }

    if !extManager.ValidateInfo(info) {
        return errors.New("扩展信息不完整")
    }

    adminVersion := config.New("version").GetString("version")

    err := version.VersionCheck(adminVersion, info.Adaptation)
    if err != nil {
        return errors.New(fmt.Sprintf("扩展[%s]适配系统版本[%s]错误", info.Adaptation, adminVersion))
    }

    if ok, err := CheckExtensionRequire(info.Require); !ok {
        return err
    }

    if model.IsInstallExtension(name) {
        return errors.New("扩展已经安装")
    }

    ip := "0.0.0.0"
    if this.Ctx != nil {
        ip = router.GetRequestIp(this.Ctx)
    }

    insertData := model.Extension{
        Name: name,
        Title: info.Title,
        Version: info.Version,
        Adaptation: info.Adaptation,
        Info: string(info.ToJSON()),
        Listorder: 100,
        Status: 0,
        UpdateTime: int(datebin.NowTime()),
        UpdateIp: ip,
        AddTime: int(datebin.NowTime()),
        AddIp: ip,
    }

    err = model.NewDB().
        Create(&insertData).
        Error
    if err != nil {
        return errors.New("安装扩展失败")
    }

    // 执行方法
    if info.Install != nil {
        info.Install()
    }

    return nil
}

// 卸载扩展
func (this *Extension) Uninstall(name string) error {
    if name == "" {
        return errors.New("扩展不能为空")
    }

    if model.IsEnableExtension(name) {
        return errors.New("扩展没有被安装或者请先禁用扩展")
    }

    // 删除
    err := model.NewExtension().
        Where("name = ?", name).
        Delete(&model.Extension{}).
        Error
    if err != nil {
        return errors.New("卸载扩展失败")
    }

    info := extension.GetManager().GetExtension(name)
    if info.Name != "" {
        // 执行方法
        if info.Uninstall != nil {
            info.Uninstall()
        }
    }

    return nil
}

// 更新扩展
func (this *Extension) Upgrade(name string) error {
    if name == "" {
        return errors.New("扩展不能为空")
    }

    installInfo := model.GetExtension(name)
    if installInfo.ID == "" {
        return errors.New("扩展没有被安装")
    }
    if installInfo.Status != 0 {
        return errors.New("更新请先禁用扩展")
    }

    extManager := extension.GetManager()

    info := extManager.GetExtension(name)
    if info.Name == "" {
        return errors.New("扩展不存在")
    }

    if !extManager.ValidateInfo(info) {
        return errors.New("扩展信息不完整")
    }

    adminVersion := config.New("version").GetString("version")

    // 检测适配版本
    err := version.VersionCheck(adminVersion, info.Adaptation)
    if err != nil {
        return errors.New(fmt.Sprintf("扩展[%s]适配系统版本[%s]错误", info.Adaptation, adminVersion))
    }

    // 检测升级版本
    err = version.VersionCheck(info.Version, fmt.Sprintf("> %s", installInfo.Version))
    if err != nil {
        return errors.New(fmt.Sprintf("扩展[%s]升级到版本[%s]错误", installInfo.Version, info.Version))
    }

    if ok, err := CheckExtensionRequire(info.Require); !ok {
        return err
    }

    ip := "0.0.0.0"
    if this.Ctx != nil {
        ip = router.GetRequestIp(this.Ctx)
    }

    err = model.NewExtension().
        Where("name = ?", name).
        Updates(map[string]any{
            "title": info.Title,
            "version": info.Version,
            "adaptation": info.Adaptation,
            "info": string(info.ToJSON()),
            "update_time": int(datebin.NowTime()),
            "update_ip": ip,
        }).
        Error
    if err != nil {
        return errors.New("更新扩展失败")
    }

    // 执行方法
    if info.Upgrade != nil {
        info.Upgrade()
    }

    return nil
}

// 启用扩展
func (this *Extension) Enable(name string) error {
    if name == "" {
        return errors.New("扩展不能为空")
    }

    info := extension.GetManager().GetExtension(name)
    if info.Name == "" {
        return errors.New("扩展不存在")
    }

    if model.IsEnableExtension(name) {
        return errors.New("扩展已经启用")
    }

    err := model.NewExtension().
        Where("name = ?", name).
        Updates(map[string]any{
            "status": 1,
        }).
        Error
    if err != nil {
        return errors.New("启用扩展失败")
    }

    // 执行方法
    if info.Enable != nil {
        info.Enable()
    }

    return nil
}

// 禁用扩展
func (this *Extension) Disable(name string) error {
    if name == "" {
        return errors.New("扩展不能为空")
    }

    info := extension.GetManager().GetExtension(name)
    if info.Name == "" {
        return errors.New("扩展不存在")
    }

    if !model.IsEnableExtension(name) {
        return errors.New("扩展已经禁用")
    }

    err := model.NewExtension().
        Where("name = ?", name).
        Updates(map[string]any{
            "status": 0,
        }).
        Error
    if err != nil {
        return errors.New("禁用扩展失败")
    }

    // 执行方法
    if info.Disable != nil {
        info.Disable()
    }

    return nil
}

// 更改排序
func (this *Extension) Listorder(name string, listorder int) error {
    if name == "" {
        return errors.New("扩展不能为空")
    }

    // 查询
    result := map[string]any{}
    err := model.NewExtension().
        Where("name = ?", name).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        return errors.New("扩展信息不存在")
    }

    err2 := model.NewExtension().
        Where("name = ?", name).
        Updates(map[string]any{
            "listorder": listorder,
        }).
        Error
    if err2 != nil {
        return errors.New("更新排序失败")
    }

    return nil
}
