package netcheck

import "syscall"

// errConnRefused is WSAECONNREFUSED, which is what a refused dial carries on
// Windows; syscall.ECONNREFUSED there is an invented number nothing returns.
const errConnRefused = syscall.Errno(10061)
