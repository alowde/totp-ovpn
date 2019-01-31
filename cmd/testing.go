package cmd

import (
	"bytes"
	"fmt"
	"github.com/alowde/totp-ovpn/user"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/cobra"
	"log"
	"os"
	"time"
)

var testingCmd = &cobra.Command{
	Use:   "test",
	Short: "Test",
	Long:  `It's a test'`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		u, err := user.FromDB(args[0])
		if err != nil {
			log.Fatalf("While loading user: %v", err)
		}

		qr, err := u.GenerateQR()
		if err != nil {
			log.Fatalf("While generating QR: %v", err)
		}

		f, err := os.Create("qr.png")
		if err != nil {
			log.Fatalf("While opening file: %v", err)
		}
		defer f.Close()

		var buf bytes.Buffer
		buf.ReadFrom(qr)
		f.Write(buf.Bytes())

		fmt.Println("Woo testing")
	},
}

var testinGCmd = &cobra.Command{
	Use:   "code",
	Short: "Test",
	Long:  `It's a test'`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		u, err := user.FromDB(args[0])
		if err != nil {
			log.Fatalf("While loading user: %v", err)
		}

		key, _ := otp.NewKeyFromURL(u.Key)
		fmt.Println(totp.GenerateCode(key.Secret(), time.Now()))

	},
}
