//go:build !windows

package netcheck

import "syscall"

// errConnRefused is what a refused dial carries; see refused_windows.go.
const errConnRefused = syscall.ECONNREFUSED
