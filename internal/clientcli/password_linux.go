// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientcli

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// passwordPipe rewraps an inherited blocking pipe in a pollable os.File so Close
// interrupts its read. Dup shares file-status flags with the original input;
// callers must not reuse that input or read concurrently from another duplicate.
func passwordPipe(input *os.File) (*os.File, error) {
	fd, err := syscall.Dup(int(input.Fd()))
	if err != nil {
		return nil, errors.New("read password: duplicate pipe")
	}
	syscall.CloseOnExec(fd)
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, errors.New("read password: configure nonblocking pipe")
	}
	reader := os.NewFile(uintptr(fd), "password input")
	// Do not proceed unless the runtime actually registered a pollable file.
	if err := reader.SetReadDeadline(time.Time{}); err != nil {
		_ = reader.Close()
		return nil, errors.New("read password: pipe cancellation unavailable")
	}
	return reader, nil
}
