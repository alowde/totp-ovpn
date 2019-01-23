package server

import (
	"fmt"
	"github.com/alowde/totp-ovpn/user"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
)

var KeyPath string = "key.pem"
var CertPath string = "cert.pem"

func Run() error {

	// Always redirect http->https
	go func() {
		if err := http.ListenAndServe(":80", http.HandlerFunc(redirectTLS)); err != nil {
			log.Fatalf("HTTP ListenAndServe error: %v", err)
		}
	}()

	http.Handle("/", http.HandlerFunc(sayHello))
	http.Handle("/qr", http.HandlerFunc(renderQR))

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

func sayHello(w http.ResponseWriter, r *http.Request) {
	fmt.Println(qrPage(w, "cat"))

}

func renderQR(w http.ResponseWriter, r *http.Request) {

	u, err := user.FromDB(r.URL.Query().Get("user"))
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
