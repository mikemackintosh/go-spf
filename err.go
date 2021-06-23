package spf

import "fmt"

type ErrSPFRecordNotFound struct {
	Domain string
}

func (err ErrSPFRecordNotFound) Error() string {
	return fmt.Sprintf("could not find SPF record for %s", err.Domain)
}

type ErrSPFValidationFailed struct {
	Domain string
}

func (err ErrSPFValidationFailed) Error() string {
	return fmt.Sprintf("could not validate SPF record for %s", err.Domain)
}

type ErrSPFRecordInvalid struct {
	Domain string
	Record string
}

func (err ErrSPFRecordInvalid) Error() string {
	return fmt.Sprintf("'%s' returned an invalid spf record, '%s'", err.Domain, err.Record)
}

type ErrDNSInvalidResolver struct {
	Resolver string
}

func (err ErrDNSInvalidResolver) Error() string {
	return fmt.Sprintf("'%s' is an invalid resolver", err.Resolver)
}
