// Package phrase writes the sentences a check reports -- "example.com -
// responded to ping in 4.1ms", "/: 93.2% used, 2.1 GiB free of 30.0 GiB" --
// in English, from a format whose placeholders are named:
//
//	phrase.T("{host} - responded to ping in {rtt}", "host", host, "rtt", rtt)
//
// A check's message is stored and sent in English: by this server, and by
// the agent on a customer's host, which knows nothing of who will read it.
// The format is also its key in the translation catalogs
// (pkg/i18n/catalog/<locale>/results*.json), and a reader's language is
// applied when the message is shown: i18n's Locale.CheckMessage finds the
// format a stored message was written from and writes it again in the
// reader's language, with the values it carried. So the formats are the
// contract between the two, and a message written with fmt.Sprintf is one no
// reader will ever see translated.
//
// It imports nothing of the application's, because the agent imports it.
package phrase

import (
	"fmt"
	"strconv"
	"strings"
)

// T fills the {placeholders} in format with the name/value pairs in args.
//
// Values are written as fmt's %v would write them -- a whole number without
// separators, an error by its Error -- so a message written with T reads
// exactly as it did when it was written with Sprintf. A number that needs a
// precision is formatted by the caller and passed as a string. A placeholder
// with no value is left showing, which is how a mistake gets noticed.
func T(format string, args ...any) string {
	if len(args) < 2 || !strings.Contains(format, "{") {
		return format
	}
	pairs := make([]string, 0, len(args))
	for i := 0; i+1 < len(args); i += 2 {
		name, ok := args[i].(string)
		if !ok {
			continue
		}
		pairs = append(pairs, "{"+name+"}", value(args[i+1]))
	}
	return strings.NewReplacer(pairs...).Replace(format)
}

func value(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case error:
		return v.Error()
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

// Mark returns format unchanged. It marks a format a message is written from
// somewhere T cannot be called -- an error wrapped with fmt.Errorf's %w, or
// the wording of one Go's standard library returns -- so that the catalogs
// still hold it, and a reader still sees the message translated.
func Mark(format string) string { return format }

// Errorf is an error whose text is T's, for a failure that ends up quoted in
// a check's message: "no greeting: {err}" is then a format its reader sees
// translated, where fmt.Errorf's would not be. Every error among the values
// is wrapped, as fmt.Errorf's %w wraps it, so errors.Is and errors.As see
// through it.
func Errorf(format string, args ...any) error {
	e := &wrapped{msg: T(format, args...)}
	for i := 1; i < len(args); i += 2 {
		if err, ok := args[i].(error); ok {
			e.errs = append(e.errs, err)
		}
	}
	return e
}

type wrapped struct {
	msg  string
	errs []error
}

func (e *wrapped) Error() string   { return e.msg }
func (e *wrapped) Unwrap() []error { return e.errs }
