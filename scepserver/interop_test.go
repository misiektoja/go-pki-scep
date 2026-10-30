//go:build interop

package scepserver_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/go-pkcs7"

	scep "github.com/misiektoja/go-pki-scep"
	"github.com/misiektoja/go-pki-scep/internal/testca"
	"github.com/misiektoja/go-pki-scep/scepserver"
)

// The interop tests run real SCEP clients against the handler. The Interop workflow builds the
// clients and sets SCEP_INTEROP=required, so a missing client fails the run instead of skipping.

// interopTool returns the path of a client binary from the environment variable or the PATH.
func interopTool(t *testing.T, env, name string) string {
	t.Helper()
	if path := os.Getenv(env); path != "" {
		return path
	}
	path, err := exec.LookPath(name)
	if err == nil {
		return path
	}
	if os.Getenv("SCEP_INTEROP") == "required" {
		t.Fatalf("%s is not on the PATH and %s is not set", name, env)
	}
	t.Skipf("%s is not on the PATH and %s is not set", name, env)
	return ""
}

// runTool runs a client in dir and fails the test with its output when it exits non-zero.
func runTool(t *testing.T, dir, tool string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(tool), strings.Join(args, " "), err, out)
	}
	t.Logf("%s %s\n%s", filepath.Base(tool), args[0], out)
}

// writePEM writes one PEM block.
func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// readDER reads a PEM or DER file and returns the DER bytes of its first block.
func readDER(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(data); block != nil {
		return block.Bytes
	}
	return data
}

// readCertificate reads a PEM or DER certificate file.
func readCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(readDER(t, path))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return cert
}

// TestSSCEP runs sscep against the handler: GetCACert, a PKCSReq that the CA keeps pending until
// the first CertPoll, GetCert and GetCRL.
func TestSSCEP(t *testing.T) {
	sscep := interopTool(t, "SSCEP", "sscep")
	ca := testca.New(t, testca.Options{Password: "interop-secret", Manual: true, ApproveAfterPolls: 1})
	ts := httptest.NewServer(newHandler(t, ca, scepserver.Options{}))
	t.Cleanup(ts.Close)
	url := ts.URL + "/scep"
	dir := t.TempDir()

	runTool(t, dir, sscep, "getcaps", "-u", url)
	runTool(t, dir, sscep, "getca", "-u", url, "-c", "ca.crt")
	caFile := "ca.crt"
	if _, err := os.Stat(filepath.Join(dir, caFile)); errors.Is(err, os.ErrNotExist) {
		caFile = "ca.crt-0"
	}
	if !readCertificate(t, filepath.Join(dir, caFile)).Equal(ca.Certificate) {
		t.Fatal("sscep getca wrote another certificate")
	}

	requester := testca.NewRequester(t, "sscep-device", "interop-secret")
	key, err := x509.MarshalPKCS8PrivateKey(requester.Key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "local.key"), "PRIVATE KEY", key)
	writePEM(t, filepath.Join(dir, "local.csr"), "CERTIFICATE REQUEST", requester.CSR.Raw)
	runTool(t, dir, sscep, "enroll", "-u", url, "-c", caFile, "-k", "local.key", "-r", "local.csr",
		"-l", "local.crt", "-E", "aes", "-S", "sha256", "-t", "1", "-n", "10")
	issued := readCertificate(t, filepath.Join(dir, "local.crt"))
	if !requester.Key.PublicKey.Equal(issued.PublicKey) {
		t.Fatal("sscep enroll wrote a certificate for another key")
	}
	if err := issued.CheckSignatureFrom(ca.Certificate); err != nil {
		t.Fatalf("issued certificate: %v", err)
	}
	if got := ca.Requests(); !slices.Equal(got, []scep.MessageType{scep.PKCSReq, scep.CertPoll}) {
		t.Errorf("CA received %v, want a PKCSReq and one CertPoll", got)
	}

	runTool(t, dir, sscep, "getcert", "-u", url, "-c", caFile, "-k", "local.key", "-l", "local.crt",
		"-s", issued.SerialNumber.String(), "-w", "fetched.crt")
	if !readCertificate(t, filepath.Join(dir, "fetched.crt")).Equal(issued) {
		t.Error("sscep getcert wrote another certificate")
	}

	runTool(t, dir, sscep, "getcrl", "-u", url, "-c", caFile, "-k", "local.key", "-l", "local.crt", "-w", "ca.crl")
	crl, err := x509.ParseRevocationList(readDER(t, filepath.Join(dir, "ca.crl")))
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(ca.Certificate); err != nil {
		t.Errorf("CRL signature: %v", err)
	}
}

// TestMicroMDMClient runs the micromdm/scep client against the handler.
func TestMicroMDMClient(t *testing.T) {
	client := interopTool(t, "MICROMDM_SCEPCLIENT", "scepclient")
	ca := testca.New(t, testca.Options{Password: "interop-secret"})
	// The micromdm/scep client encrypts with the single DES default of the CMS library it uses.
	opts := scepserver.Options{Decrypt: pkcs7.DecryptOptions{ContentEncryptionAlgorithms: []pkcs7.ContentEncryptionAlgorithm{
		pkcs7.AES128CBC, pkcs7.AES192CBC, pkcs7.AES256CBC, pkcs7.DESEDE3CBC, pkcs7.DESCBC,
	}}}
	ts := httptest.NewServer(newHandler(t, ca, opts))
	t.Cleanup(ts.Close)
	dir := t.TempDir()

	runTool(t, dir, client, "-server-url", ts.URL+"/scep", "-challenge", "interop-secret",
		"-private-key", "client.key", "-certificate", "client.crt", "-cn", "micromdm-device")
	issued := readCertificate(t, filepath.Join(dir, "client.crt"))
	if issued.Subject.CommonName != "micromdm-device" {
		t.Errorf("issued certificate subject %s", issued.Subject)
	}
	if err := issued.CheckSignatureFrom(ca.Certificate); err != nil {
		t.Errorf("issued certificate: %v", err)
	}
}
