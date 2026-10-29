//go:build interop

package scepclient_test

import (
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
