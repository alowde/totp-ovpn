package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

func init() {
	rootCmd.AddCommand(testingCmd)
	rootCmd.AddCommand(testinGCmd)
	rootCmd.AddCommand(serveCmd)
}

var rootCmd = &cobra.Command{
	Use:   "totp-ovpn",
	Short: "It's a thing",
	Long:  `blah`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("ran")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
