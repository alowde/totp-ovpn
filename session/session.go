package session

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const DefaultSessionTime = 300 // Default session time is 300 seconds
const sessionKeyLength = 20    // Session keys are 40 bytes

type session struct {
	key     []byte
	expires time.Time
}

func (s session) valid(key []byte) bool {
	if time.Now().After(s.expires) {
		return false
	}
	if !bytes.Equal(s.key, key) {
		return false
	}
	return true
}

func (s session) expired() bool {
	return time.Now().After(s.expires)
}

func newSession(duration time.Duration) (s session) {
	s.key = make([]byte, sessionKeyLength)
	rand.Read(s.key)
	s.expires = time.Now().Add(duration)
	return
}

// SessionTable is a concurrent-safe session-handling mechanism allowing the addition and validation of users with
// associated keys. Sessions expire after some time, 5 minutes by default.
type SessionTable struct {
	sessionTime time.Duration
	sessions    map[string]session
	mutex       *sync.Mutex
}

// NewSessionTable returns an initialised *SessionTable. If duration is not > 0 and < 86400 then it will be set to 300
// seconds (five minutes) by default.
func NewSessionTable(duration int) *SessionTable {
	s := new(SessionTable)
	s.sessions = make(map[string]session)
	s.mutex = new(sync.Mutex)
	s.sessionTime = DefaultSessionTime * time.Second
	if duration > 0 && duration < 86400 {
		s.sessionTime = time.Duration(duration) * time.Second
	}
	return s
}

// Add adds a user to the session table and returns a crypto-randomly generated key.
func (st *SessionTable) Add(user string) (key string) {
	st.mutex.Lock()
	st.sessions[user] = newSession(st.sessionTime)
	st.mutex.Unlock()
	return base64.StdEncoding.EncodeToString(st.sessions[user].key)
}

// Valid determines whether a user and key are associated with each other and less than sessionTime seconds old.
func (st *SessionTable) Valid(user string, key string) bool {
	st.ExpireOldSessions()
	st.mutex.Lock()
	defer st.mutex.Unlock()
	byteKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return false
	}
	if session, ok := st.sessions[user]; ok {
		if session.valid(byteKey) {
			return true
		}
	}
	return false
}

// ValidRequest wraps Valid for convenient validation of an HTTP request by checking for a valid cookie
func (st *SessionTable) ValidRequest(user string, r *http.Request) bool {
	cookie, err := r.Cookie("totp-ovpn-session")
	if err != nil {
		fmt.Println("rejected due to cookie not found")
		return false
	}
	return st.Valid(user, cookie.Value)
}

// ExpireOldSessions deletes expired sessions from the session table to avoid excessive memory use over time.
func (st *SessionTable) ExpireOldSessions() {
	st.mutex.Lock()
	for k := range st.sessions {
		if st.sessions[k].expired() {
			delete(st.sessions, k)
		}
	}
	st.mutex.Unlock()
}
