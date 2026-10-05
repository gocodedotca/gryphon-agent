//go:build !linux && !windows

package main

import "errors"

// There is no service to enrol on any other system: a Mac runs the Gryphon
// Agent app, which asks for its token itself.
func enrolHere() (enrolPlace, error) {
	return enrolPlace{}, errors.New("enrol is for Linux and Windows. On a Mac, choose Enter Token… from the Gryphon Agent menu; to run this binary by hand, give it the token in GWC_KEY_FILE")
}
