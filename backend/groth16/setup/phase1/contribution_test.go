package phase1

import (
	"bytes"
	"testing"
)

func TestContributeVerify(t *testing.T) {
	// Contribute 10 times
	nContributions := 10
	power := 8
	contributions := make([]Contribution, nContributions)
	contributions[0].Initialize(power)

	// Make contributions
	for i := 1; i < nContributions; i++ {
		contributions[i].Contribute(&contributions[i-1])
	}

	// Verify contributions
	for i := 1; i < nContributions; i++ {
		err := contributions[i].Verify(&contributions[i-1])
		if err != nil {
			t.Error(err)
		}
	}
}

func TestContributionMarshal(t *testing.T) {
	power := 8
	var c1, c2 Contribution
	c1.Initialize(power)
	var buf bytes.Buffer
	if _, err := c1.WriteTo(&buf); err != nil {
		t.Error(err)
	}
	if _, err := c2.ReadFrom(&buf); err != nil {
		t.Error(err)
	}
	
	if !bytes.Equal(HashContribution(&c1), HashContribution(&c2)) {
		t.Error("failed to correctly marshal contribution")
	}
}
