package cmd

import (
	"github.com/alowde/totp-ovpn/user"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"log"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Functions for adding, deleting and manually verifying users",
}

var addUserCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new user",
	Long:  `Call with totp-ovpn user add [name]`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := user.Add(args[0]); err != nil {
			log.Fatalln(errors.Wrap(err, "while adding new user"))
		}
	},
}

var verifyUserCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify an existing user by passcode",
	Long:  `It's a user verify function'`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		valid, err := user.Verify(args[0], args[1])
		if err != nil {
			log.Fatalln(errors.Wrap(err, "Encountered an error"))
		}
		if !valid {
			log.Fatalln(errors.New("Encountered a bug, invalid passcode"))
		}
		return
	},
}
