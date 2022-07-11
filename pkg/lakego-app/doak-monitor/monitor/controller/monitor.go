package controller

import (
    "os"
    "fmt"
    "time"
    "runtime"
    "strconv"

    "github.com/shirou/gopsutil/cpu"
    "github.com/shirou/gopsutil/disk"
    "github.com/shirou/gopsutil/host"
    "github.com/shirou/gopsutil/load"
    "github.com/shirou/gopsutil/mem"

    "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-datebin/datebin"

    "github.com/deatil/lakego-doak/lakego/router"

    adminController "github.com/deatil/lakego-doak-admin/admin/controller"
)

/**
 * 系统监控
 *
 * @create 2022-7-3
 * @author deatil
 */
type Monitor struct {
    adminController.Base
}

// 服务监控
// @Summary 服务监控详情
// @Description 服务监控详情
// @Tags 系统监控
// @Accept application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /monitor [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.monitor.index"}
func (this *Monitor) Index(ctx *router.Context) {
    // 硬件信息
    cpuNum := runtime.NumCPU() // 核心数
    var cpuUsed float64 = 0    // 用户使用率
    var cpuAvg5 float64 = 0    // CPU负载5
    var cpuAvg15 float64 = 0   // 当前空闲率

    cpuInfo, err := cpu.Percent(time.Duration(time.Second), false)
    if err == nil {
        cpuUsed, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", cpuInfo[0]), 64)
    }

    loadInfo, err := load.Avg()
    if err == nil {
        cpuAvg5, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", loadInfo.Load5), 64)
        cpuAvg15, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", loadInfo.Load15), 64)
    }

    // 内存使用信息
    var memTotal uint64 = 0  // 总内存
    var memUsed uint64 = 0   // 总内存  := 0 //已用内存
    var memFree uint64 = 0   // 剩余内存
    var memUsage float64 = 0 // 使用率

    v, err := mem.VirtualMemory()
    if err == nil {
        memTotal = v.Total
        memUsed = v.Used
        memFree = memTotal - memUsed
        memUsage, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", v.UsedPercent), 64)
    }

    // go使用内存的信息
    var goTotal uint64 = 0  // go分配的总内存数
    var goUsed uint64 = 0   // go使用的内存数
    var goFree uint64 = 0   // go剩余的内存数
    var goUsage float64 = 0 // 使用率

    var gomem runtime.MemStats
    runtime.ReadMemStats(&gomem)
    goUsed = gomem.Sys
    goUsage = goch.ToFloat64(fmt.Sprintf("%.2f", goch.ToFloat64(goUsed)/goch.ToFloat64(memTotal)*100))

    // 系统信息
    sysComputerIp := router.GetLocalIP() // 服务器IP
    sysComputerName := "" // 服务器名称
    sysOsName := ""       // 操作系统
    sysOsArch := ""       // 系统架构

    sysInfo, err := host.Info()
    if err == nil {
        sysComputerName = sysInfo.Hostname
        sysOsName = sysInfo.OS
        sysOsArch = sysInfo.KernelArch
    }

    goName := "GoLang"             // 语言环境
    goVersion := runtime.Version() // 版本

    goNowTime := datebin.Now().Timestamp() // 当前时间
    goHome := runtime.GOROOT()             // 安装路径
    goUserDir := ""                        // 项目路径

    curDir, err := os.Getwd()
    if err == nil {
        goUserDir = curDir
    }

    // 服务器磁盘信息
    diskList := make([]disk.UsageStat, 0)
    diskInfo, err := disk.Partitions(true) //所有分区
    if err == nil {
        for _, p := range diskInfo {
            diskDetail, err := disk.Usage(p.Mountpoint)
            if err == nil {
                diskDetail.UsedPercent, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", diskDetail.UsedPercent), 64)
                diskList = append(diskList, *diskDetail)
            }
        }
    }

    this.SuccessWithData(ctx, "获取成功", router.H{
        "cpuNum":          cpuNum,
        "cpuUsed":         cpuUsed,
        "cpuAvg5":         goch.ToString(cpuAvg5),
        "cpuAvg15":        goch.ToString(cpuAvg15),

        "memTotal":        memTotal,
        "memUsed":         memUsed,
        "memFree":         memFree,
        "memUsage":        memUsage,

        "goTotal":         goTotal,
        "goUsed":          goUsed,
        "goFree":          goFree,
        "goUsage":         goUsage,

        "sysComputerName": sysComputerName,
        "sysOsName":       sysOsName,
        "sysComputerIp":   sysComputerIp,
        "sysOsArch":       sysOsArch,

        "goName":          goName,
        "goVersion":       goVersion,
        "goNowTime":       goNowTime,
        "goHome":          goHome,
        "goUserDir":       goUserDir,
        "diskList":        diskList,
    })
}

