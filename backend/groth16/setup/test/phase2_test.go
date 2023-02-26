package test

import (
	"github.com/consensys/gnark/backend/groth16/setup/phase2"
	"github.com/consensys/gnark/backend/groth16/setup/phase1"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"bytes"
	"testing"
)


func Phase1Mock() phase1.Contribution {
	// Contribute 10 times
	nContributions := 10
	power := 8
	contributions := make([]phase1.Contribution, nContributions)
	contributions[0].Initialize(power)

	// Make contributions
	for i := 1; i < nContributions; i++ {
		contributions[i].Contribute(&contributions[i-1])
	}
	return contributions[nContributions-1]
}

func QAPMock() phase2.QAP {
	var qap phase2.QAP
	qap.NConstraints = 16
	qap.NPublic = 3
	qap.NWires = 20
	qap.A = make([][]fr.Element, qap.NWires)
	qap.B = make([][]fr.Element, qap.NWires)
	qap.C = make([][]fr.Element, qap.NWires)
	for i := 0; i < int(qap.NWires); i++ {
		qap.A[i] = make([]fr.Element, qap.NConstraints)
		qap.B[i] = make([]fr.Element, qap.NConstraints)
		qap.C[i] = make([]fr.Element, qap.NConstraints)
		for j := 0; j < qap.NConstraints; j++ {
			qap.A[i][j].SetRandom()
			qap.B[i][j].SetRandom()
			qap.C[i][j].SetRandom()
		}
	}
	return qap
}
func TestPhase2ContributeVerify(t *testing.T) {
	c1 := Phase1Mock()
	qap := QAPMock()

	// Contribute 10 times
	nContributions := 10
	contributions := make([]phase2.Contribution, nContributions)

	// Prepare for phase-2
	contributions[0].PreparePhase2(&c1, &qap)
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

func TestPhase2ContributionMarshal(t *testing.T) {
	srs1 := Phase1Mock()
	qap := QAPMock()
	var c1, c2, c3 phase2.Contribution
	c1.PreparePhase2(&srs1, &qap)
	c2.Contribute(&c1)

	var buf bytes.Buffer
	if _, err := c2.WriteTo(&buf); err != nil {
		t.Error(err)
	}
	if _, err := c3.ReadFrom(&buf); err != nil {
		t.Error(err)
	}
	if ! bytes.Equal(phase2.HashContribution(&c2), phase2.HashContribution(&c2)) {
		t.Error("failed to correctly marshal contribution")
	}
}
