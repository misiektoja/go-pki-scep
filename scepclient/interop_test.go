//go:build interop

package scepclient_test

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/misiektoja/go-pkcs7"

	"github.com/misiektoja/go-scep"
	"github.com/misiektoja/go-scep/internal/testca"
	"github.com/misiektoja/go-scep/scepclient"
)

// TestMicroMDMServer enrolls with a micromdm/scep server that the Interop workflow starts.
// SCEP_INTEROP_MICROMDM_URL is its URL and SCEP_INTEROP_MICROMDM_CHALLENGE its challenge password.
// With SCEP_INTEROP=required, a missing URL fails the run instead of skipping.
func TestMicroMDMServer(t *testing.T) {
	url := os.Getenv("SCEP_INTEROP_MICROMDM_URL")
	if url == "" {
		if os.Getenv("SCEP_INTEROP") == "required" {
			t.Fatal("SCEP_INTEROP_MICROMDM_URL is not set")
		}
		t.Skip("SCEP_INTEROP_MICROMDM_URL is not set")
	}
	challenge := os.Getenv("SCEP_INTEROP_MICROMDM_CHALLENGE")
	// The server answers with the single DES default of the CMS library it uses.
	client := newClient(t, url, scepclient.Options{Decrypt: pkcs7.DecryptOptions{
		ContentEncryptionAlgorithms: []pkcs7.ContentEncryptionAlgorithm{pkcs7.AES128CBC, pkcs7.DESEDE3CBC, pkcs7.DESCBC},
	}})
	ctx := t.Context()
	caps, err := client.GetCACaps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("capabilities: %v", caps)
	certs, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}

	requester := testca.NewRequester(t, "go-scep-device", challenge)
	res, err := client.Enroll(ctx, certs, enrollRequest(requester))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != scep.SUCCESS || res.Certificate == nil {
		t.Fatalf("Enroll = %s %s", res.Status, res.FailInfo)
	}
	if err := res.Certificate.CheckSignatureFrom(certs.CA); err != nil {
		t.Errorf("issued certificate: %v", err)
	}
	t.Logf("answer signed with %v, encrypted with %v", res.Response.Digest, res.Response.ContentEncryption)

	refused, err := client.Enroll(ctx, certs, enrollRequest(testca.NewRequester(t, "go-scep-device-2", challenge+"-wrong")))
	if err != nil {
		t.Fatal(err)
	}
	if refused.Status != scep.FAILURE {
		t.Errorf("Enroll with a wrong challenge = %s, want FAILURE", refused.Status)
	}
}

// TestEJBCAServer enrolls with an EJBCA Community Edition server that the Interop workflow starts.
// SCEP_INTEROP_EJBCA_URL is its SCEP URL, SCEP_INTEROP_EJBCA_CA the CA name and
// SCEP_INTEROP_EJBCA_CHALLENGE the password of the end entities go-scep-ejbca,
// go-scep-ejbca-wrong and go-scep-ejbca-none. In SCEP CA mode EJBCA takes the CSR common name as
// the end entity and its password as the challenge password.
func TestEJBCAServer(t *testing.T) {
	url := os.Getenv("SCEP_INTEROP_EJBCA_URL")
	if url == "" {
		if os.Getenv("SCEP_INTEROP") == "required" {
			t.Fatal("SCEP_INTEROP_EJBCA_URL is not set")
		}
		t.Skip("SCEP_INTEROP_EJBCA_URL is not set")
	}
	challenge := os.Getenv("SCEP_INTEROP_EJBCA_CHALLENGE")
	client := newClient(t, url, scepclient.Options{CAName: os.Getenv("SCEP_INTEROP_EJBCA_CA")})
	ctx := t.Context()
	caps, err := client.GetCACaps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("capabilities: %v", caps)
	certs, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := client.GetCACertChain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 || !bytes.Equal(chain[0].Raw, certs.CA.Raw) {
		t.Errorf("GetCACertChain returned %d certificates, want the GetCACert CA and its root", len(chain))
	} else if err := chain[0].CheckSignatureFrom(chain[1]); err != nil {
		t.Errorf("GetCACertChain: %v", err)
	}

	requester := testca.NewRequester(t, "go-scep-ejbca", challenge)
	res, err := client.Enroll(ctx, certs, enrollRequest(requester))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != scep.SUCCESS || res.Certificate == nil {
		t.Fatalf("Enroll = %s %s", res.Status, res.FailInfo)
	}
	if err := res.Certificate.CheckSignatureFrom(certs.CA); err != nil {
		t.Errorf("issued certificate: %v", err)
	}
	t.Logf("answer signed with %v, encrypted with %v", res.Response.Digest, res.Response.ContentEncryption)

	// EJBCA accepts an end entity password once, then answers with a FAILURE CertRep.
	again, err := client.Enroll(ctx, certs, enrollRequest(testca.NewRequester(t, "go-scep-ejbca", challenge)))
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != scep.FAILURE {
		t.Errorf("Enroll with a used password = %s, want FAILURE", again.Status)
	}

	// EJBCA refuses a wrong or missing password with an HTTP error and no CertRep.
	for _, tc := range []struct {
		name, cn, challenge string
		status              int
	}{
		{"wrong password", "go-scep-ejbca-wrong", challenge + "-wrong", http.StatusUnauthorized},
		{"no password", "go-scep-ejbca-none", "", http.StatusBadRequest},
	} {
		_, err := client.Enroll(ctx, certs, enrollRequest(testca.NewRequester(t, tc.cn, tc.challenge)))
		if httpErr, ok := errors.AsType[*scepclient.HTTPError](err); !ok || httpErr.StatusCode != tc.status {
			t.Errorf("Enroll with %s: err = %v, want HTTP %d", tc.name, err, tc.status)
		}
	}
}
