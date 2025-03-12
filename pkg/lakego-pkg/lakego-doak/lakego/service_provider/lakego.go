package service_provider

import (
    "github.com/deatil/lakego-doak/lakego/schedule"
    "github.com/deatil/lakego-doak/lakego/provider"

    // 脚本
    publishCmd "github.com/deatil/lakego-doak/lakego/console/publish"
    storageCmd "github.com/deatil/lakego-doak/lakego/console/storage"
    scheduleCmd "github.com/deatil/lakego-doak/lakego/console/schedule"

    // 视图
    "github.com/deatil/lakego-doak/lakego/facade"
)

/**
 * 服务提供者
 *
 * @create 2022-1-4
 * @author deatil
 */
type Lakego struct {
    provider.ServiceProvider
}

// 构造函数
func NewLakego() *Lakego {
    return &Lakego{}
}

// 引导
func (this *Lakego) Boot() {
    // 脚本
    this.loadCommand()

    // 模板渲染
    this.loadHtmlRender()
}

/**
 * 导入脚本
 */
func (this *Lakego) loadCommand() {
    // 推送
    this.AddCommand(publishCmd.PublishCmd)

    // 创建软连接
    this.AddCommand(storageCmd.StorageLinkCmd)
}

// 计划任务
func (this *Lakego) Schedule(s *schedule.Schedule) {
    // 计划任务命令
    this.AddCommand(scheduleCmd.NewScheduleCmd(s))
}

/**
 * 导入模板渲染
 */
func (this *Lakego) loadHtmlRender() {
    this.GetRoute().HTMLRender = facade.ViewHtml.GetRender()
}
