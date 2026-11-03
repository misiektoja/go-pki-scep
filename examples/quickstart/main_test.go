package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	scep "github.com/misiektoja/go-pki-scep"
	"github.com/misiektoja/go-pki-scep/scepclient"
)

// TestQuickstart enrolls and renews against the quickstart server on a free port.
func TestQuickstart(t *testing.T) {
	srv, err := start(t.Context(), "127.0.0.1:0", "secret", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.close)
	var out bytes.Buffer
	if err := enrollAndRenew(t.Context(), srv.url, srv.fingerprint, "secret", &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Enrolled CN=quickstart-device", "Renewed CN=quickstart-device"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output %q does not contain %q", out.String(), want)
		}
	}
}

// TestQuickstartRefusals covers a CA certificate that does not match the pinned fingerprint and a
// wrong challenge password.
func TestQuickstartRefusals(t *testing.T) {
	srv, err := start(t.Context(), "127.0.0.1:0", "secret", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.close)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	if err := enrollAndRenew(ctx, srv.url, [32]byte{}, "secret", io.Discard); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("enrollment with another fingerprint: error = %v", err)
	}

	client, err := scepclient.New(srv.url, scepclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = enroll(ctx, client, ca, "wrong")
	if want := scep.BadRequest.String(); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("enrollment with a wrong password: error = %v, want %s", err, want)
	}
}
