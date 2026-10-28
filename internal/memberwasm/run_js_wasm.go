// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package memberwasm

import (
	"syscall/js"

	"github.com/mandipnotroot/anonce/internal/client/keystore"
	"github.com/mandipnotroot/anonce/internal/client/membersession"
)

// Run installs one locked session in anonceMember until close is called and all
// owned pending inputs have been cleared. Use only in a trusted dedicated realm;
// promises do not make CPU-bound Go WASM work nonblocking on a browser UI thread.
func Run() {
	global := js.Global()
	if !global.Get("anonceMember").IsUndefined() {
		return
	}
	h := newHost()
	defer h.lock()
	arrays := newByteArrays()
	promise := global.Get("Promise")
	var callbacks []js.Func
	defer func() {
		for _, callback := range callbacks {
			callback.Release()
		}
	}()
	bind := func(fn func([]js.Value) any) js.Func {
		callback := js.FuncOf(func(_ js.Value, args []js.Value) any { return fn(args) })
		callbacks = append(callbacks, callback)
		return callback
	}
	// Invalid and busy calls resolve to null without starting work or retaining
	// inputs. All data-operation methods consistently return promises.
	rejected := func() any { return promise.Call("resolve", js.Null()) }
	work := func(args []js.Value, method string) any {
		unlock := method == "unlock"
		confirmed := method == "createConfirmed" || method == "backupConfirmed"
		count := 1
		if unlock {
			count = 3
		} else if confirmed {
			count = 2
		}
		if len(args) != count {
			return rejected()
		}
		views := make([]js.Value, count)
		sizes := make([]int, 3)
		for i, arg := range args {
			view, size, ok := arrays.view(arg)
			if !ok {
				return rejected()
			}
			views[i], sizes[i] = view, size
		}
		valid := validSizes(sizes[0], sizes[1], sizes[2], unlock)
		if confirmed {
			valid = validConfirmationSizes(sizes[0], sizes[1])
		}
		if !valid {
			return rejected()
		}
		op := h.begin()
		if op == nil {
			return rejected()
		}
		inputs := make([][]byte, count)
		for i, view := range views {
			inputs[i] = make([]byte, sizes[i])
			js.CopyBytesToGo(inputs[i], view)
		}
		executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
			resolve := args[0]
			go func() {
				defer h.finish(op)
				var enrollment *membersession.Enrollment
				var backup []byte
				var err error
				switch method {
				case "backup":
					backup, err = h.session.Backup(op.ctx, inputs[0])
				case "backupConfirmed":
					backup, err = h.session.BackupConfirmed(op.ctx, inputs[0], inputs[1])
				case "unlock":
					enrollment, err = h.session.Unlock(op.ctx, inputs[0], inputs[1], inputs[2])
				case "create", "createConfirmed":
					var setup *membersession.Setup
					if confirmed {
						setup, err = h.session.CreateConfirmed(op.ctx, inputs[0], inputs[1])
					} else {
						setup, err = h.session.Create(op.ctx, inputs[0])
					}
					if err == nil {
						enrollment, backup = &setup.Enrollment, setup.Backup
					}
				}
				for _, input := range inputs {
					clear(input)
				}
				// Check cancellation and publish in the same JS event turn.
				// Lock after publication cannot retract already public output.
				if !h.accepted(op) || err != nil {
					clear(backup)
					resolve.Invoke(js.Null())
					return
				}
				result := make(map[string]any)
				if enrollment != nil {
					result = arrays.enrollment(enrollment)
				}
				if backup != nil {
					result["backup"] = arrays.output(backup)
					clear(backup)
				}
				resolve.Invoke(result)
			}()
			return nil
		})
		defer executor.Release() // Promise invokes its executor synchronously.
		return promise.New(executor)
	}
	create := bind(func(args []js.Value) any { return work(args, "create") })
	createConfirmed := bind(func(args []js.Value) any { return work(args, "createConfirmed") })
	unlock := bind(func(args []js.Value) any { return work(args, "unlock") })
	backup := bind(func(args []js.Value) any { return work(args, "backup") })
	backupConfirmed := bind(func(args []js.Value) any { return work(args, "backupConfirmed") })
	request := bind(func(args []js.Value) any {
		if len(args) != 0 {
			return rejected()
		}
		op := h.begin()
		if op == nil {
			return rejected()
		}
		defer h.finish(op)
		enrollment, err := h.session.Request(op.ctx)
		if !h.accepted(op) || err != nil {
			return rejected()
		}
		return promise.Call("resolve", arrays.enrollment(enrollment))
	})
	lock := bind(func(args []js.Value) any {
		if len(args) == 0 {
			h.lock()
		}
		return nil
	})
	closeBridge := bind(func(args []js.Value) any {
		if len(args) == 0 {
			h.close()
		}
		return nil
	})
	global.Set("anonceMember", map[string]any{
		"create": create, "unlock": unlock, "backup": backup, "request": request, "lock": lock, "close": closeBridge,
		"createConfirmed": createConfirmed, "backupConfirmed": backupConfirmed,
	})
	defer global.Delete("anonceMember")
	<-h.done
}

// Use intrinsic getters, not caller-visible properties, to brand and bound
// Uint8Arrays. ArrayBuffer.isView rejects proxies without invoking their traps.
// Construct a clean view before CopyBytesToGo so shadowed buffer/offset/length
// properties cannot run getters or redirect the copy. Shared memory is excluded.
type byteArrays struct {
	uint8, isView, apply        js.Value
	length, buffer, offset, tag js.Value
	bufferLength                js.Value
}

func newByteArrays() byteArrays {
	g := js.Global()
	u := g.Get("Uint8Array")
	object := g.Get("Object")
	prototype := object.Call("getPrototypeOf", u.Get("prototype"))
	getter := func(name any) js.Value {
		return object.Call("getOwnPropertyDescriptor", prototype, name).Get("get")
	}
	return byteArrays{
		uint8: u, isView: g.Get("ArrayBuffer").Get("isView"),
		apply: g.Get("Reflect").Get("apply"), length: getter("byteLength"),
		buffer: getter("buffer"), offset: getter("byteOffset"), tag: getter(g.Get("Symbol").Get("toStringTag")),
		bufferLength: object.Call("getOwnPropertyDescriptor", g.Get("ArrayBuffer").Get("prototype"), "byteLength").Get("get"),
	}
}

func (a byteArrays) get(getter, value js.Value) js.Value {
	return a.apply.Invoke(getter, value, js.ValueOf([]any{}))
}

func (a byteArrays) view(value js.Value) (js.Value, int, bool) {
	if !a.isView.Invoke(value).Bool() || !a.get(a.tag, value).Equal(js.ValueOf("Uint8Array")) {
		return js.Undefined(), 0, false
	}
	buffer := a.get(a.buffer, value)
	if !a.ordinaryBuffer(buffer) {
		return js.Undefined(), 0, false
	}
	size := a.get(a.length, value).Int()
	// Empty/detached arrays and oversized arrays fail before constructing a view.
	if size < 1 || size > keystore.MaxPasswordSize {
		return js.Undefined(), 0, false
	}
	return a.uint8.New(buffer, a.get(a.offset, value), size), size, true
}

func (a byteArrays) ordinaryBuffer(buffer js.Value) (ok bool) {
	// The intrinsic getter brand-checks even a SharedArrayBuffer with a forged
	// ArrayBuffer prototype. Only its expected JS TypeError is input rejection.
	defer func() {
		if value := recover(); value != nil {
			if _, expected := value.(js.Error); !expected {
				panic(value)
			}
			ok = false
		}
	}()
	a.get(a.bufferLength, buffer)
	return true
}

func (a byteArrays) output(data []byte) js.Value {
	output := a.uint8.New(len(data))
	js.CopyBytesToJS(output, data)
	return output
}

func (a byteArrays) enrollment(e *membersession.Enrollment) map[string]any {
	return map[string]any{"publicKey": a.output(e.PublicKey), "csr": a.output(e.CSR)}
}
