package spf

import "fmt"

// ErrSPFRecordNotFound takes the domain that was queried and
// returns an error when the record is not found for SPF.
type ErrSPFRecordNotFound struct {
	Domain string
}

// Error retruns a string.
func (err ErrSPFRecordNotFound) Error() string {
	return fmt.Sprintf("could not find SPF record for %s", err.Domain)
}

// ErrSPFValidationFailed takes the domain that was queried and
// returns an error if it's an invalid domain.
type ErrSPFValidationFailed struct {
	Domain string
}

// Error retruns a string.
func (err ErrSPFValidationFailed) Error() string {
	return fmt.Sprintf("could not validate SPF record for %s", err.Domain)
}

// ErrSPFRecordInvalid takes the domain and SPF record and
// returns an error when the SPF record is invalid.
type ErrSPFRecordInvalid struct {
	Domain string
	Record string
}

// Error retruns a string.
func (err ErrSPFRecordInvalid) Error() string {
	return fmt.Sprintf("'%s' returned an invalid spf record, '%s'", err.Domain, err.Record)
}

// ErrDNSInvalidResolver takes the resolver you want to use and
// returns an error when it's an invalid IP.
type ErrDNSInvalidResolver struct {
	Resolver string
}

// Error retruns a string.
func (err ErrDNSInvalidResolver) Error() string {
	return fmt.Sprintf("'%s' is an invalid resolver", err.Resolver)
}
