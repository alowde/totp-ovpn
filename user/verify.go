package user

import (
	"github.com/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func Verify(passcode string, name string) (valid bool, e error) {

	u, err := FromDB(name)
	if err != nil {
		return false, errors.Wrap(err, "while searching for user")
	}

	k, _ := otp.NewKeyFromURL(u.Key)
	if totp.Validate(passcode, k.Secret()) {
		return true, nil
	}

	return false, errors.New("invalid passcode")
}
