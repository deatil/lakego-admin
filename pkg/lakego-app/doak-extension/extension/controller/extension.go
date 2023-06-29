package controller

import (
    "fmt"

    "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-datebin/datebin"

    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/facade/config"

    admin_model "github.com/deatil/lakego-doak-admin/admin/model"
    admin_controller "github.com/deatil/lakego-doak-admin/admin/controller"

    "github.com/deatil/lakego-doak-extension/extension/model"
    "github.com/deatil/lakego-doak-extension/extension/service"
    "github.com/deatil/lakego-doak-extension/extension/version"
    "github.com/deatil/lakego-doak-extension/extension/extension"
)

/**
 * 扩展
 *
 * @create 2023-4-20
 * @author deatil
 */
type Extension struct {
    admin_controller.Base
}

// 扩展列表
// @Summary 扩展列表
// @Description 扩展列表
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param searchword query string false "搜索关键字"
// @Param order      query string false "排序，示例：id__DESC"
// @Param status     query string false "状态"
// @Param start      query string false "开始数据量"
// @Param limit      query string false "每页数量"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.index"}
func (this *Extension) Index(ctx *router.Context) {
    // 模型
    extModel := model.NewExtension()

    // 排序
    order := ctx.DefaultQuery("order", "add_time__DESC")
    orders := this.FormatOrderBy(order)
    if orders[0] == "" ||
        (orders[0] != "id" &&
        orders[0] != "add_time") {
        orders[0] = "add_time"
    }

    extModel = extModel.Order(orders[0] + " " + orders[1])

    // 时间条件
    startTime := ctx.DefaultQuery("start_time", "")
    if startTime != "" {
        extModel = extModel.Where("add_time >= ?", this.FormatDate(startTime))
    }

    endTime := ctx.DefaultQuery("end_time", "")
    if endTime != "" {
        extModel = extModel.Where("add_time <= ?", this.FormatDate(endTime))
    }

    // 搜索条件
    searchword := ctx.DefaultQuery("searchword", "")
    if searchword != "" {
        searchword = "%" + searchword + "%"

        extModel = extModel.Where(
            model.NewDB().
                Where("name LIKE ?", searchword).
                Where("title LIKE ?", searchword).
                Or("info LIKE ?", searchword),
        )
    }

    status := this.SwitchStatus(ctx.DefaultQuery("status", ""))
    if status != -1 {
        extModel = extModel.Where("status = ?", status)
    }

    // 分页相关
    start := ctx.DefaultQuery("start", "0")
    limit := ctx.DefaultQuery("limit", "10")

    newStart := goch.ToInt(start)
    newLimit := goch.ToInt(limit)

    extModel = extModel.
        Offset(newStart).
        Limit(newLimit)

    list := make([]map[string]any, 0)

    // 列表
    extModel.Find(&list)

    var total int64

    // 总数
    err := extModel.
        Offset(-1).
        Limit(-1).
        Count(&total).
        Error
    if err != nil {
        this.Error(ctx, "获取失败")
        return
    }

    this.SuccessWithData(ctx, "获取成功", router.H{
        "start": start,
        "limit": limit,
        "total": total,
        "list": list,
    })
}

// 本地扩展
// @Summary 本地扩展
// @Description 本地扩展
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/local [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.local"}
func (this *Extension) Local(ctx *router.Context) {
    exts := extension.GetManager().GetExtensions()
    total := len(exts)

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

    this.SuccessWithData(ctx, "获取成功", router.H{
        "total": total,
        "list": newExts,
    })
}

// 安装扩展
// @Summary 安装扩展
// @Description 安装扩展
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param name query string true "扩展名称"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/:name/install [post]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.install"}
func (this *Extension) Inatll(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "扩展不能为空")
        return
    }

    extManager := extension.GetManager()

    info := extManager.GetExtension(name)
    if info.Name == "" {
        this.Error(ctx, "扩展不存在")
        return
    }

    if !extManager.ValidateInfo(info) {
        this.Error(ctx, "扩展信息不完整")
        return
    }

    adminVersion := config.New("version").GetString("version")

    err := version.VersionCheck(adminVersion, info.Adaptation)
    if err != nil {
        this.Error(ctx, fmt.Sprintf("扩展[%s]适配系统版本[%s]错误", info.Adaptation, adminVersion))
        return
    }

    if ok, err := service.CheckExtensionRequire(info.Require); !ok {
        this.Error(ctx, err.Error())
        return
    }

    if model.IsInstallExtension(name) {
        this.Error(ctx, "扩展已经安装")
        return
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
        UpdateIp: router.GetRequestIp(ctx),
        AddTime: int(datebin.NowTime()),
        AddIp: router.GetRequestIp(ctx),
    }

    err = model.NewDB().
        Create(&insertData).
        Error
    if err != nil {
        this.Error(ctx, "安装扩展失败")
        return
    }

    // 执行方法
    if info.Install != nil {
        info.Install()
    }

    this.Success(ctx, "安装扩展成功")
}

// 卸载扩展
// @Summary 卸载扩展
// @Description 卸载扩展
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param name query string true "扩展名称"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/:name/uninstall [delete]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.uninstall"}
func (this *Extension) Uninstall(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "扩展不能为空")
        return
    }

    if model.IsEnableExtension(name) {
        this.Error(ctx, "扩展没有被安装或者请先禁用扩展")
        return
    }

    // 删除
    err := model.NewExtension().
        Where("name = ?", name).
        Delete(&model.Extension{}).
        Error
    if err != nil {
        this.Error(ctx, "卸载扩展失败")
        return
    }

    info := extension.GetManager().GetExtension(name)
    if info.Name != "" {
        // 执行方法
        if info.Uninstall != nil {
            info.Uninstall()
        }
    }

    this.Success(ctx, "卸载扩展成功")
}

// 更新扩展
// @Summary 更新扩展
// @Description 更新扩展
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param name query string true "扩展名称"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/:name/upgrade [put]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.upgrade"}
func (this *Extension) Upgrade(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "扩展不能为空")
        return
    }

    installInfo := model.GetExtension(name)
    if installInfo.ID == "" {
        this.Error(ctx, "扩展没有被安装")
        return
    }
    if installInfo.Status != 0 {
        this.Error(ctx, "更新请先禁用扩展")
        return
    }

    extManager := extension.GetManager()

    info := extManager.GetExtension(name)
    if info.Name == "" {
        this.Error(ctx, "扩展不存在")
        return
    }

    if !extManager.ValidateInfo(info) {
        this.Error(ctx, "扩展信息不完整")
        return
    }

    adminVersion := config.New("version").GetString("version")

    // 检测适配版本
    err := version.VersionCheck(adminVersion, info.Adaptation)
    if err != nil {
        this.Error(ctx, fmt.Sprintf("扩展[%s]适配系统版本[%s]错误", info.Adaptation, adminVersion))
        return
    }

    // 检测升级版本
    err = version.VersionCheck(info.Version, fmt.Sprintf("> %s", installInfo.Version))
    if err != nil {
        this.Error(ctx, fmt.Sprintf("扩展[%s]升级版本[%s]错误", installInfo.Version, info.Version))
        return
    }

    if ok, err := service.CheckExtensionRequire(info.Require); !ok {
        this.Error(ctx, err.Error())
        return
    }

    err = model.NewExtension().
        Where("name = ?", name).
        Updates(map[string]any{
            "title": info.Title,
            "version": info.Version,
            "adaptation": info.Adaptation,
            "info": string(info.ToJSON()),
            "update_time": int(datebin.NowTime()),
            "update_ip": router.GetRequestIp(ctx),
        }).
        Error
    if err != nil {
        this.Error(ctx, "更新扩展失败")
        return
    }

    // 执行方法
    if info.Upgrade != nil {
        info.Upgrade()
    }

    this.Success(ctx, "更新扩展成功")
}

// 扩展排序
// @Summary 扩展排序
// @Description 扩展排序
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param name      query string true "扩展名称"
// @Param listorder formData string true "排序值"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/:name/sort [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.sort"}
func (this *Extension) Listorder(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "扩展不能为空")
        return
    }

    // 查询
    result := map[string]any{}
    err := model.NewExtension().
        Where("name = ?", name).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "扩展信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]any)
    this.ShouldBindJSON(ctx, &post)

    // 排序
    listorder := 0
    if post["listorder"] != "" {
        listorder = goch.ToInt(post["listorder"])
    } else {
        listorder = 100
    }

    err2 := model.NewExtension().
        Where("name = ?", name).
        Updates(map[string]any{
            "listorder": listorder,
        }).
        Error
    if err2 != nil {
        this.Error(ctx, "更新排序失败")
        return
    }

    this.Success(ctx, "更新排序成功")
}

// 启用扩展
// @Summary 启用扩展
// @Description 启用扩展
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param name query string true "扩展名称"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/:name/enable [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.enable"}
func (this *Extension) Enable(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "扩展不能为空")
        return
    }

    info := extension.GetManager().GetExtension(name)
    if info.Name == "" {
        this.Error(ctx, "扩展不存在")
        return
    }

    if model.IsEnableExtension(name) {
        this.Error(ctx, "扩展已经启用")
        return
    }

    err := model.NewExtension().
        Where("name = ?", name).
        Updates(map[string]any{
            "status": 1,
        }).
        Error
    if err != nil {
        this.Error(ctx, "启用扩展失败")
        return
    }

    // 执行方法
    if info.Enable != nil {
        info.Enable()
    }

    this.Success(ctx, "启用扩展成功")
}

// 禁用扩展
// @Summary 禁用扩展
// @Description 禁用扩展
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param name query string true "扩展名称"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/:name/disable [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.disable"}
func (this *Extension) Disable(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "扩展不能为空")
        return
    }

    info := extension.GetManager().GetExtension(name)
    if info.Name == "" {
        this.Error(ctx, "扩展不存在")
        return
    }

    if !model.IsEnableExtension(name) {
        this.Error(ctx, "扩展已经禁用")
        return
    }

    err := model.NewExtension().
        Where("name = ?", name).
        Updates(map[string]any{
            "status": 0,
        }).
        Error
    if err != nil {
        this.Error(ctx, "禁用扩展失败")
        return
    }

    // 执行方法
    if info.Disable != nil {
        info.Disable()
    }

    this.Success(ctx, "禁用扩展成功")
}
