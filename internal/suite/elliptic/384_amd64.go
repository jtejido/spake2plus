// +build arm64 amd64

package elliptic

import (
	el "crypto/elliptic"
	"github.com/cloudflare/circl/ecc/p384"
)

func P384() el.Curve {
	return p384.P384()
}
