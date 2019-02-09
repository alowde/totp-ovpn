package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
	"io"
	"math/big"
	"time"
)

// parseCert attempts to handle all the acceptable encodings for a certificate (PEM, encrypted PEM, DER)
func parseCert(certRaw *bytes.Buffer, password []byte) (cert *x509.Certificate, err error) {

	var der []byte

	// If we can decode the cert as a PEM file use the first resulting decoded block
	// Otherwise hope it's a DER-encoded blob
	certPEMBlock, _ := pem.Decode(certRaw.Bytes())
	if certPEMBlock == nil {
		return x509.ParseCertificate(certRaw.Bytes())
	}

	if password == nil && x509.IsEncryptedPEMBlock(certPEMBlock) {
		return nil, errors.New("encrypted certificate but no password provided")
	}

	if password != nil && x509.IsEncryptedPEMBlock(certPEMBlock) {
		if der, err = x509.DecryptPEMBlock(certPEMBlock, []byte(password)); err != nil {
			return nil, errors.Wrap(err, "unable to decrypt certificate")
		}
	} else {
		der = certPEMBlock.Bytes
	}

	return x509.ParseCertificate(der)
}

// parseKey attempts to handle RSA and ECDSA private keys in:
// - raw DER encoding
// - PEM encoded DER
// - PEM encoded DER with PEM encryption (RSA only)
// - DER in a PEM encoded, unencrypted PKCS#8 container
// We don't attempt to handle encrypted PKCS#8 containers due to lack of stdlib support.
func parseKey(keyRaw *bytes.Buffer, password []byte) (key interface{}, err error) {

	// If we can decode the cert as a PEM file use the first resulting decoded block
	// Otherwise hope it's a DER-encoded blob and try parsing it as an RSA or ECDSA key
	keyPEMBlock, _ := pem.Decode(keyRaw.Bytes())
	if keyPEMBlock == nil {
		if key, err := x509.ParsePKCS1PrivateKey(keyRaw.Bytes()); err == nil {
			return key, err
		}
		if key, err := x509.ParseECPrivateKey(keyRaw.Bytes()); err == nil {
			return key, err
		}
		return nil, errors.New("unknown file format")
	}

	if x509.IsEncryptedPEMBlock(keyPEMBlock) {
		if password == nil {
			return nil, errors.New("encrypted key but no password provided")
		}

		// ECDSA keys are normally only stored encrypted in a PKCS#8 container, and we don't support encrypted PKCS#8
		if keyPEMBlock.Type != "RSA PRIVATE KEY" {
			return nil, errors.New("unsupported encrypted key type")
		}
		// Annoyingly DecryptPemBlock gives us the ASN.1 data instead of a PEM block for inconsistency
		der, err := x509.DecryptPEMBlock(keyPEMBlock, password)
		if err != nil {
			return nil, errors.Wrap(err, "unable to decrypt key")
		}
		return x509.ParsePKCS1PrivateKey(der)
	}

	switch keyPEMBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyPEMBlock.Bytes)
	case "PRIVATE KEY": // PKCS#8 container, supports RSA and ECDSA keys only but doesn't tell us which it will return
		return x509.ParsePKCS8PrivateKey(keyPEMBlock.Bytes)
	case "EC PRIVATE KEY": // Plain PEM formatted ECDSA key
		return x509.ParseECPrivateKey(keyPEMBlock.Bytes)
	}

	return nil, errors.New("unknown/unsupported key type")
}

// CA is a CA certificate with corresponding private key.
type CA struct {
	cert *x509.Certificate
	key  interface{}
}

// NewCAFromReaders accepts an io.Reader for the certificate and key to be used for signing certificates, as well as an
// optional password to decode the received certificate/key. It handles both RSA and ECDSA keys and attempts to read
// un/encrypted PEM data, raw ASN.1 DER bytes and unencrypted PKCS#8 containers.
func NewCAFromReaders(certReader io.Reader, keyReader io.Reader, password string) (result *CA, err error) {

	result = new(CA)

	var certRaw = new(bytes.Buffer)
	_, _ = io.Copy(certRaw, certReader)
	if result.cert, err = parseCert(certRaw, []byte(password)); err != nil {
		return nil, err
	}

	var keyRaw = new(bytes.Buffer)
	_, _ = io.Copy(keyRaw, keyReader)
	if result.key, err = parseKey(keyRaw, []byte(password)); err != nil {
		return nil, err
	}

	return
}

// SignRequest signs a Request object, replacing the contained certificate with a signed copy of the contained CSR. It
// guarantees a valid certificate will be produced but does not validate the parameters of the certificate.
func (c *CA) SignRequest(req *Request) (err error) {

	serialBytes := make([]byte, 20)
	if _, err := rand.Read(serialBytes); err != nil {
		return errors.Wrap(err, "could not generate random serialBytes")
	}
	serial := new(big.Int)
	serial.SetBytes(serialBytes)

	var certTemplate = x509.Certificate{
		Signature:          req.csr.Signature,
		SignatureAlgorithm: req.csr.SignatureAlgorithm,

		PublicKeyAlgorithm: req.csr.PublicKeyAlgorithm,
		PublicKey:          req.csr.PublicKey,

		SerialNumber: serial,
		Issuer:       c.cert.Subject,
		Subject:      req.csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // TODO: Make configurable
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	crtRaw, err := x509.CreateCertificate(rand.Reader, &certTemplate, c.cert, req.csr.PublicKey, c.key)
	if err != nil {
		return errors.Wrap(err, "unable to sign certificate request")
	}

	if req.crt, err = x509.ParseCertificate(crtRaw); err != nil {
		return errors.Wrap(err, "unable to parse signed certificate data")
	}

	return nil
}
