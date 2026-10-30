package scepserver_test

import (
	"net/http"
	"testing"

	"github.com/misiektoja/go-pkcs7"

	"github.com/misiektoja/go-pki-scep/internal/testca"
	"github.com/misiektoja/go-pki-scep/scepserver"
)

// FuzzPKIOperation posts arbitrary bodies to the handler. Malformed input must be refused with a
// client error or a CertRep, never with a panic or an internal error.
func FuzzPKIOperation(f *testing.F) {
	ca := testca.New(f, testca.Options{})
	handler := newHandler(f, ca, scepserver.Options{})
	valid := pkcsReq(f, ca, pkcs7.EncryptOptions{}).Raw
	f.Add(valid)
	f.Add(valid[:len(valid)/2])
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		rec := serve(handler, http.MethodPost, "/scep?operation=PKIOperation", body)
		if rec.Code >= http.StatusInternalServerError {
			t.Errorf("HTTP %d for a %d-byte body", rec.Code, len(body))
		}
	})
}
