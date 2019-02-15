package user

import (
	"bytes"
	"github.com/asdine/storm"
	"github.com/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"image/png"
	"io"
	"log"
)

type User struct {
	Key         string
	Username    string `storm:"id"`
	Password    []byte
	Initialised bool
}

type ErrUserNotFound struct {
	err error
}

func (e ErrUserNotFound) Error() string {
	return e.err.Error()
}

func New(name, password string) *User {
	var u = new(User)

	k, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "totp-ovpn",
		AccountName: name,
	})
	if err != nil {
		log.Panic("failed to gen key")
	}
	u.Key = k.URL()
	u.Username = name
	if err := u.SetPassword(password); err != nil {
		log.Panicf("unexpected error while trying to set password: %s", err)
	}
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
		if err == storm.ErrNotFound {
			return nil, ErrUserNotFound{err}
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

func (u *User) SetPassword(password string) error {
	var err error
	if u.Password, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost); err != nil {
		return errors.Wrap(err, "failed to set password")
	}
	return nil
}

func (u *User) ValidatePassword(password string) error {
	return bcrypt.CompareHashAndPassword(u.Password, []byte(password))
}
