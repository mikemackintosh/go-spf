package spf

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mikemackintosh/go-spf/testing/dns"
)

func init() {

	go dns.Run()

	resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, network, "127.0.0.1:8053")
		},
	}
}

func TestErrSPFRecordNotFound(t *testing.T) {
	err := ErrSPFRecordNotFound{
		Domain: "angrystatic.com",
	}

	if err.Error() != "could not find SPF record for angrystatic.com" {
		t.Errorf("ErrSPFRecordNotFound does not match %s", err.Error())
	}
}

func TestErrSPFValidationFailed(t *testing.T) {
	err := ErrSPFValidationFailed{
		Domain: "angrystatic.com",
	}

	if err.Error() != "could not validate SPF record for angrystatic.com" {
		t.Errorf("ErrSPFValidationFailed does not match %s", err.Error())
	}
}

func TestErrSPFRecordInvalid(t *testing.T) {
	err := ErrSPFRecordInvalid{
		Domain: "fail.mikemackintosh.com",
	}

	if !strings.Contains(err.Error(), "invalid spf record") {
		t.Errorf("ErrSPFRecordInvalid does not match %s", err.Error())
	}
}

func TestGet(t *testing.T) {
	if _, err := Get("mikemackintosh.com"); err != nil {
		t.Errorf("error getting spf record: %s", err)
	}
}

func TestSetResolver(t *testing.T) {
	var ctx = context.Background()
	err := SetResolver("127.0.0.1:8053")
	if err != nil {
		t.Errorf("error setting resolver: %s", err)
	}

	r, err := resolver.LookupTXT(ctx, "mikemackintosh.com")
	if err != nil {
		t.Errorf("error querying test server: %s", err)
	}
	if r[0] != "v=spf1 include:_spf.google.com ~all" {
		t.Errorf("error with response record, got: %s", r)

	}
}

func TestValidate(t *testing.T) {
	var err error
	var s *SpfRecord
	err = SetResolver("127.0.0.1:8053")
	if err != nil {
		t.Errorf("error setting resolver: %s", err)
	}

	s, err = Get("mikemackintosh.com")
	if err != nil {
		t.Errorf("error: %s", err)
	}

	var ip string
	ip = "10.1.1.1"
	res, _ := s.Validate(ip)
	if res != RESULT_SOFTFAIL {
		t.Errorf("%s evaluated to '%s', expected %s", ip, res, RESULT_SOFTFAIL)
	}

	ip = "127.0.0.16"
	res, _ = s.Validate(ip)
	if res != RESULT_PASS {
		t.Errorf("%s evaluated to '%s', expected %s", ip, res, RESULT_PASS)
	}
}
