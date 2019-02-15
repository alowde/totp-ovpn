package cmd

import (
	"github.com/alowde/totp-ovpn/user"
	"github.com/asdine/storm"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"log"
)

func init() {
	rootCmd.AddCommand(userCmd)
	userCmd.AddCommand(addUserCmd)
	userCmd.AddCommand(verifyUserCmd)
	userCmd.AddCommand(listUsersCmd)

	listUsersCmd.Flags().BoolVar(&IncSensitive, "include-sensitive", false, "Include sensitive information")
}

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Functions for adding, deleting and manually verifying users",
}

var addUserCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new user",
	Long:  `Call with totp-ovpn user add [name] [password]`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		db, err := storm.Open("my.db")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		tx, err := db.Begin(true)
		if err != nil {
			log.Fatalf("Encountered an error while starting a DB transaction: %s\n", err)
		}
		defer tx.Rollback()

		var u = new(user.User)
		// A not found error is fine, anything else we'll assume is fatal
		if err := db.One("Username", args[0], u); err != nil {
			if err != storm.ErrNotFound {
				log.Fatalf("Encountered an error while querying database: %s\n", err)
			}
		}
		if u.Initialised {
			log.Fatalf("User %s already exists and is initialised, refusing to overwrite.\n", args[0])
		}
		u = user.New(args[0], args[1])
		if err := tx.Save(u); err != nil {
			log.Fatalf("Warning: error while writing to database. User data may be inconsistent. Error: %s\n", err)
		}
		if err := tx.Commit(); err != nil {
			log.Fatalf("Error while committing to DB: %s\n", err)
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
