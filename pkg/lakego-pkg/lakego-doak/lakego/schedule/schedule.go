package schedule

import (
    "fmt"
    "time"
    "sync"
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
    logger := PrintfLogger(NewLogger())

    cron := NewCron(
        WithSeconds(),
        WithChain(Recover(logger)),
    )

    schedule := &Schedule{
        Cron:    cron,
        entries: make([]*Entry, 0),
        cronIDs: make(map[string]CronEntryID),
        stoped:  make(map[string]CronEntry),
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
    // 锁定
    mu sync.RWMutex

    // 计划任务
    Cron *Cron

    // 添加的数据列表
    entries []*Entry

    // 计划任务 id 列表
    cronIDs map[string]CronEntryID

    // 已停止的计划任务
    stoped map[string]CronEntry
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

// 获取数据
func (this *Schedule) GetEntry(name string) *Entry {
    for _, entry := range this.entries {
        if entry.Name == name {
            return entry
        }
    }

    return &Entry{}
}

// 移除数据
func (this *Schedule) RemoveEntry(name string) {
    var entries []*Entry

    for _, entry := range this.entries {
        if entry.Name != name {
            entries = append(entries, entry)
        }
    }

    this.entries = entries
}

// 全部任务数据
func (this *Schedule) Entries() []*Entry {
    return this.entries
}

// 设置日志
func (this *Schedule) SetShowLogInfo(logInfo bool) *Schedule {
    var logger CronLogger

    if logInfo {
        logger = PrintfLogger(NewLogger())
    } else {
        logger = VerbosePrintfLogger(NewLogger())
    }

    return this.WithOption(WithLogger(logger))
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
        this.mu.Lock()

        if entry.Name != "" {
            this.cronIDs[fmt.Sprintf("cron_run_%d", entryID)] = entryID
        } else {
            this.cronIDs[entry.Name] = entryID
        }

        this.mu.Unlock()
    }

    if err != nil {
        fmt.Println(err.Error())
    }
}

// 停止
func (this *Schedule) Stop() context.Context {
    return this.Cron.Stop()
}

// 任务时区
func (this *Schedule) CronLocation() *time.Location {
    return this.Cron.Location()
}

// 计划任务已添加任务列表
func (this *Schedule) CronEntries() []CronEntry {
    return this.Cron.Entries()
}

// 计划任务已添加单个任务
func (this *Schedule) CronEntry(name string) CronEntry {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if id, ok := this.cronIDs[name]; ok {
        return this.Cron.Entry(id)
    }

    return CronEntry{}
}

// 任务删除
func (this *Schedule) CronRemove(name string) {
    if id, ok := this.cronIDs[name]; ok {
        this.Cron.Remove(id)
    }

    this.mu.Lock()

    delete(this.cronIDs, name)
    delete(this.stoped, name)

    this.mu.Unlock()
}

// 任务开启
func (this *Schedule) CronStart(name string) {
    if entry, ok := this.stoped[name]; ok {
        if entry.Valid() {
            // 添加计划任务
            entryID := this.Cron.Schedule(entry.Schedule, entry.Job)

            this.mu.Lock()

            delete(this.stoped, name)
            this.cronIDs[name] = entryID

            this.mu.Unlock()
        }
    }
}

// 任务停止
func (this *Schedule) CronStop(name string) {
    if id, ok := this.cronIDs[name]; ok {
        entry := this.Cron.Entry(id)
        if entry.Valid() {
            this.Cron.Remove(id)

            this.mu.Lock()

            this.stoped[name] = entry
            delete(this.cronIDs, name)

            this.mu.Unlock()
        }
    }
}

// 计划任务 ID 列表
func (this *Schedule) CronIDs() map[string]CronEntryID {
    return this.cronIDs
}

// 计划任务名称列表
func (this *Schedule) CronIDNames() []string {
    var names []string

    for name, _ := range this.cronIDs {
        names = append(names, name)
    }

    return names
}

// 计划任务单个 ID
func (this *Schedule) CronID(name string) CronEntryID {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if id, ok := this.cronIDs[name]; ok {
        return id
    }

    return 0
}
