package cmd

import (
	"fmt"
	"github.com/alowde/totp-ovpn/server"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run or configure server",
	Long:  `Run the built-in web server'`,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		fmt.Println(server.Run())

	},
}
