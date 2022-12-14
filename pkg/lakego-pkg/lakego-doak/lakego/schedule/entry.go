package schedule

import (
    "strings"
)

// 构造函数
func NewEntry() *Entry {
    return &Entry{
        Spec: "* * * * * *",
    }
}

/**
 * 计划任务内容，任务时间用的最低秒
 *
 * @create 2022-11-29
 * @author deatil
 */
type Entry struct {
    // 计划时间
    Spec string

    // Schedule
    Schedule ISchedule

    // 脚本
    Cmd any

    // 当前任务名称
    Name string
}

// 设置计划时间
func (this *Entry) Cron(spec string) *Entry {
    this.Spec = spec

    return this
}

// 设置计划时间
func (this *Entry) WithSpec(spec string) *Entry {
    this.Spec = spec

    return this
}

// 设置脚本
func (this *Entry) WithCmd(cmd any) *Entry {
    this.Cmd = cmd

    return this
}

// 设置名称
func (this *Entry) WithName(name string) *Entry {
    this.Name = name

    return this
}

// 函数
func (this *Entry) AddFunc(cmd func()) *Entry {
    return this.WithCmd(cmd)
}

// Job 接口类
func (this *Entry) AddJob(cmd IJob) *Entry {
    return this.WithCmd(cmd)
}

// Schedule
func (this *Entry) AddSchedule(schedule ISchedule, cmd IJob) *Entry {
    this.Schedule = schedule

    return this.WithCmd(cmd)
}

// Yearly
func (this *Entry) CronYearly() *Entry {
    this.Spec = "@yearly"

    return this
}

// annually
func (this *Entry) CronAnnually() *Entry {
    this.Spec = "@annually"

    return this
}

// monthly
func (this *Entry) CronMonthly() *Entry {
    this.Spec = "@monthly"

    return this
}

// weekly
func (this *Entry) CronWeekly() *Entry {
    this.Spec = "@weekly"

    return this
}

// daily
func (this *Entry) CronDaily() *Entry {
    this.Spec = "@daily"

    return this
}

// midnight
func (this *Entry) CronMidnight() *Entry {
    this.Spec = "@midnight"

    return this
}

// hourly
func (this *Entry) CronHourly() *Entry {
    this.Spec = "@hourly"

    return this
}

// every
func (this *Entry) Every(date string) *Entry {
    this.Spec = "@every " + date

    return this
}

func (this *Entry) EverySecond() *Entry {
    return this.SpliceIntoPosition(1, "*")
}

func (this *Entry) EveryTwoSeconds() *Entry {
    return this.SpliceIntoPosition(1, "*/2")
}

func (this *Entry) EveryThreeSeconds() *Entry {
    return this.SpliceIntoPosition(1, "*/3")
}

func (this *Entry) EveryFourSeconds() *Entry {
    return this.SpliceIntoPosition(1, "*/4")
}

func (this *Entry) EveryFiveSeconds() *Entry {
    return this.SpliceIntoPosition(1, "*/5")
}

func (this *Entry) EveryTenSeconds() *Entry {
    return this.SpliceIntoPosition(1, "*/10")
}

func (this *Entry) EveryFifteenSeconds() *Entry {
    return this.SpliceIntoPosition(1, "*/15")
}

func (this *Entry) EveryThirtySeconds() *Entry {
    return this.SpliceIntoPosition(1, "0,30")
}

func (this *Entry) EveryMinute() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "*")
}

func (this *Entry) EveryTwoMinutes() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "*/2")
}

func (this *Entry) EveryThreeMinutes() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "*/3")
}

func (this *Entry) EveryFourMinutes() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "*/4")
}

func (this *Entry) EveryFiveMinutes() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "*/5")
}

func (this *Entry) EveryTenMinutes() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "*/10")
}

func (this *Entry) EveryFifteenMinutes() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "*/15")
}

func (this *Entry) EveryThirtyMinutes() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "0,30")
}

func (this *Entry) Hourly() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "0")
}

func (this *Entry) HourlyAt(offset ...string) *Entry {
    offsetString := "*"

    if len(offset) > 1 {
        offsetString = strings.Join(offset, ",")
    } else if len(offset) == 1 {
        offsetString = offset[0]
    }

    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, offsetString)
}

func (this *Entry) EveryTwoHours() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "0").
                SpliceIntoPosition(3, "*/2")
}

func (this *Entry) EveryThreeHours() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "0").
                SpliceIntoPosition(3, "*/3")
}

func (this *Entry) EveryFourHours() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "0").
                SpliceIntoPosition(3, "*/4")
}

func (this *Entry) EverySixHours() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "0").
                SpliceIntoPosition(3, "*/6")
}

func (this *Entry) Daily() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "0").
                SpliceIntoPosition(3, "0")
}

func (this *Entry) At(time string) *Entry {
    return this.DailyAt(time)
}

func (this *Entry) DailyAt(time string) *Entry {
    segments := strings.Split(time, ":")

    value := "0"
    if len(segments) == 2 {
        value = segments[1]
    }

    return this.SpliceIntoPosition(3, segments[0]).
                SpliceIntoPosition(2, value).
                SpliceIntoPosition(1, "0")
}

func (this *Entry) TwiceDaily(first, second string) *Entry {
    return this.TwiceDailyAt(first, second, "0")
}

func (this *Entry) TwiceDailyAt(first, second, offset string) *Entry {
    hours := first + "," + second

    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, offset).
                SpliceIntoPosition(3, hours)
}

func (this *Entry) Weekdays() *Entry {
    return this.Days(MONDAY + "-" + FRIDAY)
}

func (this *Entry) Weekends() *Entry {
    return this.Days(SATURDAY + "," + SUNDAY)
}

func (this *Entry) Mondays() *Entry {
    return this.Days(MONDAY)
}

func (this *Entry) Tuesdays() *Entry {
    return this.Days(TUESDAY)
}

func (this *Entry) Wednesdays() *Entry {
    return this.Days(WEDNESDAY)
}

func (this *Entry) Thursdays() *Entry {
    return this.Days(THURSDAY)
}

func (this *Entry) Fridays() *Entry {
    return this.Days(FRIDAY)
}

func (this *Entry) Saturdays() *Entry {
    return this.Days(SATURDAY)
}

func (this *Entry) Sundays() *Entry {
    return this.Days(SUNDAY)
}

func (this *Entry) Weekly() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "0").
                SpliceIntoPosition(3, "0").
                SpliceIntoPosition(5, "0")
}

func (this *Entry) WeeklyOn(dayOfWeek, time string) *Entry {
    this.DailyAt(time)

    return this.Days(dayOfWeek)
}

func (this *Entry) Monthly() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "0").
                SpliceIntoPosition(3, "0").
                SpliceIntoPosition(4, "1")
}

func (this *Entry) MonthlyOn(dayOfMonth, time string) *Entry {
    this.DailyAt(time)

    return this.SpliceIntoPosition(4, dayOfMonth)
}

func (this *Entry) TwiceMonthly(first, second, time string) *Entry {
    daysOfMonth := first + "," + second

    this.DailyAt(time)

    return this.SpliceIntoPosition(4, daysOfMonth)
}

func (this *Entry) Quarterly() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "0").
                SpliceIntoPosition(3, "0").
                SpliceIntoPosition(4, "1").
                SpliceIntoPosition(5, "1-12/3")
}

func (this *Entry) Yearly() *Entry {
    return this.SpliceIntoPosition(1, "0").
                SpliceIntoPosition(2, "0").
                SpliceIntoPosition(3, "0").
                SpliceIntoPosition(4, "1").
                SpliceIntoPosition(5, "1")
}

func (this *Entry) YearlyOn(month, dayOfMonth, time string) *Entry {
    this.DailyAt(time)

    return this.SpliceIntoPosition(4, dayOfMonth).
                SpliceIntoPosition(5, month)
}

// days
func (this *Entry) Days(days ...string) *Entry {
    return this.SpliceIntoPosition(6, strings.Join(days, " "))
}

// 更改位置
func (this *Entry) SpliceIntoPosition(position uint, value string) *Entry {
    segments := strings.Split(this.Spec, " ")

    segments[position - 1] = value

    this.Spec = strings.Join(segments, " ")

    return this
}
