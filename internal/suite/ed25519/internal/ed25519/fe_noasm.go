// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64, generic

package ed25519

func FeMul(v, x, y *FieldElement) { feMulGeneric(v, x, y) }

func FeSquare(v, x *FieldElement) { feSquareGeneric(v, x) }
