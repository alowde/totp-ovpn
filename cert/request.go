package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
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

func parseCSR(csrRaw *bytes.Buffer) (csr *x509.CertificateRequest, err error) {

	// If we can't decode the CSR as PEM data try just parsing it as a DER blob
	csrPEMBlock, _ := pem.Decode(csrRaw.Bytes())
	if csrPEMBlock == nil {
		return x509.ParseCertificateRequest(csrRaw.Bytes())
	}

	return x509.ParseCertificateRequest(csrPEMBlock.Bytes)

}

type Request struct {
	csr      *x509.CertificateRequest
	crt      *x509.Certificate
	Username string
	signed   bool
}

func NewRequestFromReader(r io.Reader) (req *Request, err error) {

	req = new(Request)
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, r)
	if err != nil {
		return nil, errors.Wrap(err, "while reading")
	}

	if req.csr, err = parseCSR(buf); err != nil {
		return nil, errors.Wrap(err, "while decoding CSR")
	}

	req.Username = req.csr.Subject.CommonName

	// Only valid usernames as per https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4
	// are allowed in the Common Name field
	if ok, _ := regexp.Match("^[0-9A-Za-z_.@-]+$", []byte(req.Username)); !ok {
		fmt.Println(req.Username)
		return nil, InvalidNameError{}
	}

	return req, nil
}
