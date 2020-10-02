// +build !arm64, !amd64

package elliptic

import (
	el "crypto/elliptic"
)

func P384() el.Curve {
	return el.P384()
}
