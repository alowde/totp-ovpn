package user

import (
	"bytes"
	"github.com/asdine/storm"
	"github.com/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"image/png"
	"io"
	"log"
)

type User struct {
	Key         string
	Username    string `storm:"id"`
	Initialised bool
}

func New(name string) *User {
	var u = new(User)

	k, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "totp-ovpn",
		AccountName: name,
	})
	if err != nil {
		panic("failed to gen key")
	}
	u.Key = k.URL()
	u.Username = name

	return u
}

func FromDB(name string) (*User, error) {
	db, err := storm.Open("my.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var u = new(User)
	if err := db.One("Username", name, u); err != nil {
		if err.Error() == storm.ErrNotFound.Error() {
			return nil, errors.New("user not found")
		}
		return nil, errors.Wrap(err, "while querying DB for user")
	}
	return u, nil
}

func (u *User) GenerateQR() (io.Reader, error) {

	key, err := otp.NewKeyFromURL(u.Key)
	if err != nil {
		return nil, errors.Wrap(err, "while generating QR code parameters")
	}

	var buf = new(bytes.Buffer)
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, errors.Wrap(err, "while generating QR code image")
	}
	png.Encode(buf, img)
	return buf, nil
}
