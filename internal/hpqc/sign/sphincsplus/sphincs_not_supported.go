//go:build windows

package sphincsplus

import "github.com/gh4rib/pqpg/internal/hpqc/sign"

func Scheme() sign.Scheme {
	return nil
}
