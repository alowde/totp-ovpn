package user

import (
	"github.com/asdine/storm"
	"github.com/pkg/errors"
	"log"
)

type AlreadyInitialised error

func Add(name string) (err error) {
	db, err := storm.Open("my.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	tx, err := db.Begin(true)
	if err != nil {
		return errors.Wrap(err, "while starting a DB transaction")
	}
	defer tx.Rollback()

	var u = new(User)
	// A not found error is fine, anything else we'll assume is fatal
	if err := db.One("Username", name, u); err != nil {
		if err != storm.ErrNotFound {
			return errors.Wrap(err, "while querying database")
		}
	}
	if u.Initialised {
		return AlreadyInitialised(errors.New("refusing to overwrite initialised user"))
	}
	u = New(name)
	if err := tx.Save(u); err != nil {
		return errors.Wrap(err, "while writing to database (users data may be inconsistent)")
	}

	return errors.Wrap(tx.Commit(), "while committing to DB")
}
