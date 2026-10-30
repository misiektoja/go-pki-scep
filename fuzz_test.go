package scep_test

import (
	"crypto/x509"
	"testing"

	"github.com/misiektoja/go-pkcs7"

	scep "github.com/misiektoja/go-pki-scep"
)

// FuzzParsePKIMessage checks that parsing and decrypting hostile messages returns errors instead
// of panicking.
func FuzzParsePKIMessage(f *testing.F) {
	f.Add(readTestFile(f, "PKCSReq.der"))
	f.Add(readTestFile(f, "CertRep.der"))
	f.Add(readTestFile(f, "testca2/CertRep_NoCertificatesForSigners.der"))
	// The fixture CA has a 4096-bit key, which is too slow under fuzzing instrumentation, so the
	// seed that reaches decryption is built for a smaller test CA.
	ca := newTestCA(f)
	device := newTestRequester(f, "secret")
	req, err := scep.NewCSRRequest(scep.PKCSReq, device.csr, device.requestOptions(ca))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(req.Raw)
	f.Fuzz(func(_ *testing.T, data []byte) {
		for _, opts := range []scep.ParseOptions{{AllowMD5: true, LegacyCertificateParser: true}, {Signers: []*x509.Certificate{ca.cert}}} {
			msg, err := scep.ParsePKIMessage(data, opts)
			if err != nil {
				continue
			}
			_ = msg.DecryptPKIEnvelope(ca.cert, ca.key, pkcs7.DecryptOptions{})
			_, _ = msg.Fail(scep.BadRequest, ca.responseOptions())
		}
	})
}
