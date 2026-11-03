# Getting started

This page builds a SCEP server and a client in one Go program and then enrolls against the same
server with an independent client. Each part of the program is a place where your own code goes
later. The table after the program names the guide page for each one.

The server keeps everything in memory and signs with a throwaway RSA CA that it creates at
startup. It issues a certificate for every PKCSReq that carries the challenge password and for
every RenewalReq signed with a certificate it issued. It serves plain HTTP on the loopback address.
SCEP signs and encrypts each message, so the challenge password does not travel in clear text.

## What you need

* Go 1.27.3 or newer, the minimum the module declares
* Port 8080 free on 127.0.0.1 or another address passed with `-addr`
* For step 3, [certrally](https://misiektoja.github.io/certrally/) or another SCEP client

## Step 1: create the program

Create a module and add the library:

```bash
mkdir scep-quickstart && cd scep-quickstart
go mod init example.com/scep-quickstart
go get github.com/misiektoja/go-pki-scep
```

The same program is in the repository as
[examples/quickstart](https://github.com/misiektoja/go-pki-scep/tree/main/examples/quickstart),
where `go run ./examples/quickstart` starts it without any setup. Save it as `main.go`:

```go
--8<-- "examples/quickstart/main.go"
```

Record the packages it imports in `go.mod`:

```bash
go mod tidy
```

| Part | What the quickstart does | What replaces it |
| --- | --- | --- |
| `quickstartCA.Enroll` | Compares the challenge password with one fixed value and accepts a RenewalReq signed with any certificate it issued | Your authorization policy, see [Implementing a CA](server/implementing-a-ca.md) |
| `quickstartCA.issue` | Signs a one-day client certificate with an in-memory key | Your CA and its certificate profiles |
| `quickstartCA.Responder` | Signs answers and decrypts requests with the CA key | The CA key or an RA, see [Implementing a CA](server/implementing-a-ca.md#responders-and-ras) |
| `quickstartCA.Poll` | Refuses every CertPoll, because nothing is ever pending | A store of pending requests, see [Pending requests and throttling](server/pending-requests.md) |
| `checkCACertificates` | Pins a fingerprint the program knows because it created the CA | A fingerprint distributed out of band, see [CA certificates and trust](client/ca-certificates.md) |
| `enroll` and `renew` | Enroll a new RSA key and renew its certificate | The device side, see [Enrollment and renewal](client/enrollment.md) |

## Step 2: run it

```bash
go run .
```

The program enrolls and renews once with the client, prints the server URL and the fingerprint of
the CA certificate and keeps serving until you press Ctrl+C:

```text
Enrolled CN=quickstart-device with serial 17480416376858012702
Renewed CN=quickstart-device with serial 17122936644825487411
Serving http://127.0.0.1:8080/scep with the challenge password "secret".
CA certificate SHA-256 fingerprint: 9d46bf304ffba20208369bc0279776c6a97d06bc95b368abc42a8a165b4c22cb
Press Ctrl+C to stop.
```

The handler logs every PKIOperation answer to standard error:

```text
time=2026-11-03T15:06:53.661+01:00 level=INFO msg="scep request answered" message_type="PKCSReq (19)" transaction_id=b181e23f076b96349c0f9a7f5a2bd48c9166d0c0 status="SUCCESS (0)"
time=2026-11-03T15:06:53.717+01:00 level=INFO msg="scep request answered" message_type="RenewalReq (17)" transaction_id=5cf166dc4765384224c6a14442b5beef4ed759ea status="SUCCESS (0)"
```

The serial numbers, the transaction IDs and the fingerprint change on every run, because the CA
and the keys are created at startup. Ask the server for its capabilities:

```bash
curl 'http://127.0.0.1:8080/scep?operation=GetCACaps'
```

```text
AES
DES3
POSTPKIOperation
Renewal
SCEPStandard
SHA-1
SHA-256
SHA-512
```

[Server options](reference/server-options.md#capabilities) explains how the handler derives this
list.

## Step 3: enroll with another client

Leave the server running. In a second terminal, enroll with certrally. Replace `FINGERPRINT` with
the fingerprint the server printed, so certrally refuses any other CA certificate:

```bash
certrally scep enroll --server http://127.0.0.1:8080/scep --fingerprint FINGERPRINT --challenge secret --subject CN=device-1 --cert-out device.pem --key-out device.key
```

Renew the certificate with a RenewalReq signed by it:

```bash
certrally scep renew --server http://127.0.0.1:8080/scep --fingerprint FINGERPRINT --cert device.pem --key device.key --cert-out device-new.pem --key-out device-new.key
```

A request with another challenge password gets a FAILURE answer with `badRequest`. The server log
shows the cause, which is not sent to the client:

```text
time=2026-11-03T15:06:54.157+01:00 level=INFO msg="scep request answered" message_type="PKCSReq (19)" transaction_id=B485DB38004DF987172810E833FB1BB48D72867B status="FAILURE (2)" fail_info="badRequest (2)" cause="wrong challenge password"
```

With `--key-type ecdsa-p256` certrally signs the request with a separate RSA key, because the
answer is encrypted for the certificate that signed the request. The CA still issues the
certificate for the ECDSA key in the CSR. These commands were checked by hand with certrally
v0.4.2. CI does not run them.

## Before production

The quickstart leaves out what a real CA needs:

* **Authorization.** One fixed challenge password lets anyone who knows it enroll any subject.
  Issue one-time passwords per device and check the requested subject. Check that the certificate
  that signs a RenewalReq is not revoked.
* **Keys.** The CA key lives in memory. Keep it in your CA or an HSM. `Responder.SignerKey` is a
  `crypto.Signer` and `Responder.DecrypterKey` a `crypto.Decrypter`, so neither has to leave the
  device that holds it.
* **Trust distribution.** Devices need the CA fingerprint before their first request, through
  provisioning or an MDM profile.
* **Limits.** The handler does not rate limit clients. Put middleware in front of it, as
  [Security model](security/security-model.md) describes.
