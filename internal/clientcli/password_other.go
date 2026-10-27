// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package clientcli

import (
	"errors"
	"os"
)

// Inherited-pipe cancellation has only been implemented and tested on Linux.
func passwordPipe(_ *os.File) (*os.File, error) {
	return nil, errors.New("read password: pipe input requires native Linux")
}
