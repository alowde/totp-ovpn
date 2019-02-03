package cert

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"regexp"
)

type InvalidNameError struct{}

func (i InvalidNameError) Error() string {
	return "invalid name"
}

type InvalidDERCSR struct{ msg string }

func (i InvalidDERCSR) Error() string {
	return i.msg
}
func NewInvalidDERCSR(err error) InvalidDERCSR {
	i := InvalidDERCSR{
		msg: fmt.Sprintf("not a valid DER-encoded certificate signing request: %s", err.Error()),
	}
	return i
}

type Request struct {
	csr      *x509.CertificateRequest
	crt      *x509.Certificate
	username string
	signed   bool
}

func NewRequestFromReader(r *io.Reader) (req *Request, err error) {

	req = new(Request)
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, *r)

	req.csr, err = x509.ParseCertificateRequest(buf.Bytes())
	if err != nil {
		return nil, NewInvalidDERCSR(err)
	}

	req.username = req.csr.Subject.CommonName

	// Only valid usernames as per https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4
	// are allowed in the Common Name field
	if ok, _ := regexp.Match("^[0-9A-Za-z_.@-]+$", []byte(req.username)); !ok {
		fmt.Println(req.username)
		return nil, InvalidNameError{}
	}

	return req, nil
}
