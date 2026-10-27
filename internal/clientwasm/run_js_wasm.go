// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package clientwasm

import "syscall/js"

// Run installs the development-only anonce interface until its close method is
// called. The loading realm and its built-ins must be trusted. Existing globals
// are not overwritten. Each instance requires a separate realm or prior shutdown.
func Run() {
	global := js.Global()
	if !global.Get("anonce").IsUndefined() {
		return
	}
	object := global.Get("Object")
	stringType := global.Get("String")
	done := make(chan struct{})
	closed := false
	verify := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if closed || len(args) != 1 {
			return nil
		}
		// Boxing preserves object identity. Reject those values before reading
		// properties so proxies/getters cannot run. Inspect only trusted boxed
		// primitives, including BigInt, which syscall/js.Type does not support.
		boxed := object.Invoke(args[0])
		if boxed.Equal(args[0]) || !boxed.Get("constructor").Equal(stringType) || boxed.Length() != encodedRequestSize {
			return nil
		}
		// Bound the primitive string before copying its UTF-8 encoding into Go.
		public, err := verifyHex(args[0].String())
		if err != nil {
			return nil
		}
		return public
	})
	defer verify.Release()
	shutdown := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) == 0 && !closed {
			closed = true
			close(done)
		}
		return nil
	})
	defer shutdown.Release()
	global.Set("anonce", map[string]any{"verifyCSR": verify, "close": shutdown})
	defer global.Delete("anonce")
	<-done
}
