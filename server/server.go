package server

import (
	"fmt"
	"github.com/alowde/totp-ovpn/cert"
	"github.com/alowde/totp-ovpn/session"
	"github.com/alowde/totp-ovpn/user"
	"github.com/pkg/errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
)

var KeyPath string = "key.pem"
var CertPath string = "cert.pem"

var MaxCSRSize int64 = 10 * 1024

var sessionTable *session.SessionTable

func Run() error {

	sessionTable = session.NewSessionTable(0)

	// Always redirect http->https
	go func() {
		if err := http.ListenAndServe(":80", http.HandlerFunc(redirectTLS)); err != nil {
			log.Fatalf("HTTP ListenAndServe error: %v", err)
		}
	}()

	http.Handle("/", http.HandlerFunc(renderEnrollUser))
	http.Handle("/qr", http.HandlerFunc(renderQR))
	http.Handle("/upload-csr", http.HandlerFunc(acceptCSR))
	http.Handle("/verify-2fa", http.HandlerFunc(verify2FA))

	if err := http.ListenAndServeTLS(":443", CertPath, KeyPath, nil); err != nil {
		return err
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	<-signalChan

	return nil
}

func redirectTLS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusFound)
}

func renderEnrollUser(w http.ResponseWriter, _ *http.Request) {
	fmt.Println(renderPageEnrollUser(w))
}

// Render a QR image that encodes a user's TOTP secret
func renderQR(w http.ResponseWriter, r *http.Request) {
	formUser := r.URL.Query().Get("user")

	if !sessionTable.ValidRequest(formUser, r) {
		http.Error(w, "nope", http.StatusNotFound)
		return
	}

	u, err := user.FromDB(formUser)
	if err != nil {
		http.Error(w, "nope", http.StatusNotFound)
		return
	}

	qr, err := u.GenerateQR()
	if err != nil {
		http.Error(w, "nope", http.StatusInternalServerError)
		return
	}
	_, _ = io.Copy(w, qr)
}

func acceptCSR(w http.ResponseWriter, r *http.Request) {
	// We don't expect to receive files larger than an 8K certificate
	if r.ContentLength > MaxCSRSize {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	// MaxBytesReader protects against broken/malicious clients
	r.Body = http.MaxBytesReader(w, r.Body, 10*1024)
	_ = r.ParseMultipartForm(10 * 1024)
	file, _, err := r.FormFile("fileToUpload")
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	defer file.Close()

	req, err := cert.NewRequestFromReader(io.Reader(file))
	if err != nil {
		fmt.Println(err)
		return
	}

	u, err := user.FromDB(req.Username)
	if err != nil {
		if _, ok := errors.Cause(err).(user.ErrUserNotFound); ok {
			w.WriteHeader(http.StatusForbidden)
			_ = renderPageAuthError(w, "user or password invalid")
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := u.ValidatePassword(r.PostForm.Get("password")); err != nil {
		w.WriteHeader(http.StatusForbidden)
		_ = renderPageAuthError(w, "user or password invalid")
		return
	}

	// User and password are OK, create a session cookie and allow the enrollment of a QR code
	cookie := http.Cookie{
		Name:     "totp-ovpn-session",
		Value:    sessionTable.Add(u.Username),
		MaxAge:   session.DefaultSessionTime,
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &cookie)
	_ = renderPageQR(w, u.Username)
	return
}

func verify2FA(w http.ResponseWriter, r *http.Request) {
	renderPage2FAFail(w)
}
