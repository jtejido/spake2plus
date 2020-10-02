// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64, !generic

package ed25519

//go:noescape
// FeMul calculates out = a * b.
func FeMul(out, a, b *FieldElement)

//go:noescape
// FeSquare calculates out = a * a.
func FeSquare(out, a *FieldElement)
