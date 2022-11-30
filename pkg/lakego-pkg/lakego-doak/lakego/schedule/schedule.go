package schedule

import (
    "fmt"
    "time"
    "context"
)

// 常量
const (
    SUNDAY    = "0";
    MONDAY    = "1";
    TUESDAY   = "2";
    WEDNESDAY = "3";
    THURSDAY  = "4";
    FRIDAY    = "5";
    SATURDAY  = "6";
)

// 构造函数
func New() *Schedule {
    c := NewCron(WithSeconds())

    schedule := &Schedule{
        Cron:    c,
        entries: make([]*Entry, 0),
    }

    return schedule
}

/**
 * 计划任务
 *
 * @create 2022-11-29
 * @author deatil
 */
type Schedule struct {
    // 计划任务
    Cron *Cron

    // 添加的数据列表
    entries []*Entry

    // 计划任务 id 列表
    cronIDs []int
}

// 添加计划任务
func (this *Schedule) WithCron(c *Cron) *Schedule {
    this.Cron = c

    return this
}

// 添加数据
func (this *Schedule) WithEntry(entry *Entry) *Schedule {
    this.entries = append(this.entries, entry)

    return this
}

// 清空数据
func (this *Schedule) ClearEntries() *Schedule {
    this.entries = make([]*Entry, 0)

    return this
}

// 批量设置
func (this *Schedule) WithOption(opts ...Option) *Schedule {
    for _, opt := range opts {
        opt(this.Cron)
    }

    return this
}

// 设置时区
func (this *Schedule) SetLocation(loc string) *Schedule {
    timeLoc, _ := time.LoadLocation(loc)

    return this.WithOption(WithLocation(timeLoc))
}

// AddFunc
func (this *Schedule) AddFunc(cmd func()) *Entry {
    entry := NewEntry().AddFunc(cmd)

    this.entries = append(this.entries, entry)

    return entry
}

// AddJob
func (this *Schedule) AddJob(cmd IJob) *Entry {
    entry := NewEntry().AddJob(cmd)

    this.entries = append(this.entries, entry)

    return entry
}

// AddSchedule
func (this *Schedule) AddSchedule(schedule ISchedule, cmd IJob) *Entry {
    entry := NewEntry().AddSchedule(schedule, cmd)

    this.entries = append(this.entries, entry)

    return entry
}

// 开启
func (this *Schedule) Start() {
    this.addEntries()

    this.Cron.Start()
}

// 运行
func (this *Schedule) Run() {
    this.addEntries()

    this.Cron.Run()
}

// 添加全部任务数据
func (this *Schedule) addEntries() {
    for _, entry := range this.entries {
        this.addEntry(entry)
    }
}

// 添加任务数据
func (this *Schedule) addEntry(entry *Entry) {
    if (entry.Spec == "" && entry.Schedule == nil) ||
        entry.Cmd == nil {
        return
    }

    var entryID CronEntryID
    var err error

    switch cmd := entry.Cmd.(type) {
        // 方法
        case func():
            entryID, err = this.Cron.AddFunc(entry.Spec, cmd)

        // job 结构体
        case IJob:
            if entry.Spec != "" {
                // 字符
                entryID, err = this.Cron.AddJob(entry.Spec, cmd)
            } else if entry.Schedule != nil {
                // Schedule 结构体
                entryID = this.Cron.Schedule(entry.Schedule, cmd)
            }
    }

    if err == nil {
        this.cronIDs = append(this.cronIDs, int(entryID))
    }

    if err != nil {
        fmt.Println(err.Error())
    }
}

// 停止
func (this *Schedule) Stop() context.Context {
    return this.Cron.Stop()
}

// 计划任务 ID 列表
func (this *Schedule) CronIDs() []int {
    return this.cronIDs
}
