package schedule

import (
    "github.com/robfig/cron/v3"
)

var (
    // New
    NewCron = cron.New

    // 设置
    WithLocation = cron.WithLocation
    WithSeconds  = cron.WithSeconds
    WithParser   = cron.WithParser
    WithChain    = cron.WithChain
    WithLogger   = cron.WithLogger

    // 解析
    NewParser     = cron.NewParser
    ParseStandard = cron.ParseStandard

    // Chain
    NewChain = cron.NewChain
    Recover  = cron.Recover
    DelayIfStillRunning = cron.DelayIfStillRunning
    SkipIfStillRunning  = cron.SkipIfStillRunning

    // Every
    Every = cron.Every

    // 日志
    DefaultLogger = cron.DefaultLogger
    DiscardLogger = cron.DiscardLogger

    PrintfLogger        = cron.PrintfLogger
    VerbosePrintfLogger = cron.VerbosePrintfLogger
)

// 结构体
type (
    Cron         = cron.Cron
    Option       = cron.Option
    SpecSchedule = cron.SpecSchedule

    Parser = cron.Parser

    JobWrapper = cron.JobWrapper
    Chain      = cron.Chain

    ConstantDelaySchedule = cron.ConstantDelaySchedule

    CronEntryID = cron.EntryID
    CronEntry   = cron.Entry

    CronLogger  = cron.Logger
)

// 接口
type (
    IJob      = cron.Job
    ISchedule = cron.Schedule
    IFuncJob  = cron.FuncJob
)
