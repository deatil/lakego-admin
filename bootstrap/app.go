package bootstrap

import (
    "os"
    "github.com/spf13/cobra"

    "lakego-admin/lakego/app"
    providerInterface "lakego-admin/lakego/provider/interfaces"
    adminProvider "lakego-admin/admin/provider/admin"
)

var newApp *app.App

var rootCmd = &cobra.Command{
    Use: "lakego-admin",
    Short: "lakego-admin",
    SilenceUsage: true,
    Long: `lakego-admin`,
    Args: func(cmd *cobra.Command, args []string) error {
        return nil
    },
    PersistentPreRunE: func(*cobra.Command, []string) error {
        return nil
    },
    Run: func(cmd *cobra.Command, args []string) {
        // admin 后台路由
        adminServiceProvider := &adminProvider.ServiceProvider{}
        newApp.Register(func() providerInterface.ServiceProvider {
            return adminServiceProvider
        })

        newApp.Run()
    },
}

// Execute : apply commands
func Execute() {
    newApp = app.New()

    newApp.WithRootCmd(rootCmd)

    if err := rootCmd.Execute(); err != nil {
        os.Exit(-1)
    }
}

