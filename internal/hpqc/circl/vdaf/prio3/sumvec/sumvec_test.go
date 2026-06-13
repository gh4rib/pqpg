package sumvec

import (
	"testing"

	"github.com/gh4rib/pqpg/internal/hpqc/circl/internal/test"
	"github.com/gh4rib/pqpg/internal/hpqc/circl/vdaf/prio3/internal/flp_test"
)

func TestSumVec(t *testing.T) {
	t.Run("Query", func(t *testing.T) {
		s, err := newFlpSumVec(4, 4, 3)
		test.CheckNoErr(t, err, "new flp failed")
		flp_test.TestInvalidQuery(t, &s.FLP)
	})
}
