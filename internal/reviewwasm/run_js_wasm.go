// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package reviewwasm owns local, round-scoped browser cryptographic operations.
package reviewwasm

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/subtle"
	"syscall/js"
	"time"

	"github.com/mandipnotroot/anonce/internal/client/reviewerkey"
	"github.com/mandipnotroot/anonce/internal/reviewprofile"
)

// Run is used only in a dedicated worker. Its one bounded operation copies all
// byte inputs before returning a Promise, wipes them before settlement, and never
// exposes a private key. The host terminates on cancellation and expiry.
func Run() {
	g := js.Global()
	if !g.Get("anonceReview").IsUndefined() {
		return
	}
	var b reviewprofile.Bulletin
	var raw, private, token, envelope []byte
	var pending *reviewprofile.Pending
	var round []byte
	defer func() { clear(private); clear(token) }()
	uint8 := g.Get("Uint8Array")
	arrayBuffer := g.Get("ArrayBuffer")
	promise := g.Get("Promise")
	busy := false
	output := func(data []byte) js.Value { v := uint8.New(len(data)); js.CopyBytesToJS(v, data); return v }
	view := func(v js.Value) ([]byte, bool) {
		if !arrayBuffer.Call("isView", v).Bool() || !v.InstanceOf(uint8) {
			return nil, false
		}
		// The trusted worker validates cloned arrays, including shared backing.
		n := v.Get("byteLength").Int()
		if n < 1 || n > 8192 || !v.Get("buffer").InstanceOf(arrayBuffer) {
			return nil, false
		}
		out := make([]byte, n)
		if js.CopyBytesToGo(out, v) != n {
			clear(out)
			return nil, false
		}
		return out, true
	}
	call := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if busy || len(args) < 1 || args[0].Type() != js.TypeString || len(args) > 5 {
			return promise.Call("resolve", js.Null())
		}
		method := args[0].String()
		bounds := map[string][][2]int{
			"inspect": {{564, 1587}, {32, 32}}, "prepare": {{564, 1587}, {32, 32}}, "finalize": {{384, 384}}, "encrypt": {{1, 4000}}, "submission": {}, "receipt": {{200, 200}},
			"reviewerCreate": {{1, 1024}, {1, 1024}, {16, 16}}, "reviewerUnlock": {{1, 1024}, {108, 108}, {564, 1587}, {32, 32}}, "reviewerBind": {{564, 1587}, {32, 32}}, "proof": {{81, 81}}, "decrypt": {{4145, 4145}},
		}
		sizes, ok := bounds[method]
		if !ok || len(args) != len(sizes)+1 {
			return promise.Call("resolve", js.Null())
		}
		inputs := make([][]byte, len(sizes))
		for i, size := range sizes {
			var valid bool
			inputs[i], valid = view(args[i+1])
			if !valid || len(inputs[i]) < size[0] || len(inputs[i]) > size[1] {
				for _, v := range inputs {
					clear(v)
				}
				return promise.Call("resolve", js.Null())
			}
		}
		busy = true
		executor := js.FuncOf(func(_ js.Value, p []js.Value) any {
			resolve := p[0]
			go func() {
				defer func() {
					for _, v := range inputs {
						clear(v)
					}
					busy = false
				}()
				var result any
				var err error
				ctx := context.Background()
				switch method {
				case "inspect", "prepare", "reviewerBind", "reviewerUnlock":
					i := 0
					if method == "reviewerUnlock" {
						i = 2
					}
					var parsed reviewprofile.Bulletin
					parsed, err = reviewprofile.ParseBulletin(inputs[i], inputs[i+1])
					if err != nil {
						break
					}
					if method == "inspect" {
						result = map[string]any{"id": output(parsed.ID[:]), "question": parsed.Question}
						break
					}
					if method == "prepare" {
						if pending != nil || len(token) > 0 || len(private) > 0 {
							err = reviewprofile.ErrInvalid
							break
						}
						var blinded []byte
						blinded, pending, err = reviewprofile.Prepare(parsed, inputs[0])
						if err == nil {
							b = parsed
							raw = bytes.Clone(inputs[0])
							result = map[string]any{"blinded": output(blinded)}
						}
						break
					}
					if method == "reviewerUnlock" {
						if !time.Now().Before(parsed.ReviewUntil) {
							err = reviewprofile.ErrInvalid
							break
						}
						if len(private) > 0 {
							err = reviewprofile.ErrInvalid
							break
						}
						private, err = reviewerkey.Open(ctx, inputs[0], inputs[1])
						if err != nil {
							break
						}
					} else if !bytes.Equal(round, parsed.ID[:]) {
						err = reviewprofile.ErrInvalid
						break
					}
					var k *ecdh.PrivateKey
					k, err = ecdh.X25519().NewPrivateKey(private)
					if err != nil || !bytes.Equal(k.PublicKey().Bytes(), parsed.Reviewer) {
						clear(private)
						private = nil
						err = reviewprofile.ErrInvalid
						break
					}
					b = parsed
					raw = bytes.Clone(inputs[i])
					round = bytes.Clone(b.ID[:])
					result = map[string]any{"unlocked": true}
				case "finalize":
					if pending == nil {
						err = reviewprofile.ErrInvalid
						break
					}
					token, err = pending.Finalize(inputs[0])
					if err == nil {
						pending = nil
						result = map[string]any{"authorized": true}
					}
				case "encrypt":
					if len(token) == 0 || len(envelope) > 0 {
						err = reviewprofile.ErrInvalid
						break
					}
					envelope, err = reviewprofile.Seal(b, raw, inputs[0])
					if err == nil {
						result = map[string]any{"token": output(token), "envelope": output(envelope)}
					}
				case "submission":
					if len(token) == 0 || len(envelope) == 0 {
						err = reviewprofile.ErrInvalid
						break
					}
					result = map[string]any{"token": output(token), "envelope": output(envelope)}
				case "receipt":
					err = reviewprofile.VerifyReceipt(b, raw, token, envelope, inputs[0])
					if err == nil {
						result = map[string]any{"verified": true}
					}
				case "reviewerCreate":
					if len(private) > 0 || len(token) > 0 || subtle.ConstantTimeCompare(inputs[0], inputs[1]) != 1 {
						err = reviewprofile.ErrInvalid
						break
					}
					var generated, backup []byte
					generated, err = reviewerkey.Generate(ctx)
					if err != nil {
						break
					}
					backup, err = reviewerkey.Seal(ctx, inputs[0], generated)
					if err != nil {
						clear(generated)
						break
					}
					private = generated
					round = bytes.Clone(inputs[2])
					k, e := ecdh.X25519().NewPrivateKey(private)
					if e != nil {
						err = e
						break
					}
					result = map[string]any{"publicKey": output(k.PublicKey().Bytes()), "backup": output(backup)}
					clear(backup)
				case "proof", "decrypt":
					if !time.Now().Before(b.ReviewUntil) {
						clear(private)
						private = nil
						err = reviewprofile.ErrInvalid
						break
					}
					if len(raw) == 0 || len(private) == 0 {
						err = reviewprofile.ErrInvalid
						break
					}
					var pt []byte
					pt, err = reviewprofile.Open(raw, private, inputs[0], method == "proof")
					if err == nil {
						result = map[string]any{"bytes": output(pt)}
						clear(pt)
					}
				}
				for _, v := range inputs {
					clear(v)
				}
				if err != nil || result == nil {
					resolve.Invoke(js.Null())
				} else {
					resolve.Invoke(result)
				}
			}()
			return nil
		})
		defer executor.Release()
		return promise.New(executor)
	})
	defer call.Release()
	g.Set("anonceReview", call)
	defer g.Delete("anonceReview")
	select {}
}
