package schedule

import (
    "fmt"

    "github.com/deatil/go-datebin/datebin"

    "github.com/deatil/lakego-doak/lakego/color"
    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/schedule"
)

/**
 * 执行计划任务
 *
 * > ./main lakego:schedule
 * > main.exe lakego:schedule
 * > go run main.go lakego:schedule
 *
 * @create 2022-11-30
 * @author deatil
 */
var ScheduleCmd = &command.Command{
    Use: "lakego:schedule",
    Short: "执行计划任务。",
    Example: "{execfile} lakego:schedule",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {
    },
    Run: func(cmd *command.Command, args []string) {

    },
}

// 构造函数
func NewScheduleCmd(s *schedule.Schedule) *command.Command {
    ScheduleCmd.Run = func(cmd *command.Command, args []string) {
        nowDate := datebin.Now().ToDatetimeString()

        s.Start()
        defer s.Stop()

        ids := s.CronIDs()
        cronCount := fmt.Sprintf("%d", len(ids))

        fmt.Print("\n")
        color.
            NewWithOption(
                color.ForegroundOption("green"),
                color.BaseOption("bold"),
                color.BaseOption("blinkRapid"),
            ).
            Print("[" + nowDate + "] 计划任务共 " + cronCount + " 条已开始运行...")
        fmt.Print("\n")

        select {}
    }

    return ScheduleCmd
}
