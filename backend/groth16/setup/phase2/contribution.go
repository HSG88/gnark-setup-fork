package phase2

import (
	"crypto/sha256"
	"math/big"

	"github.com/consensys/gnark/backend/groth16/setup/phase1"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	utils "github.com/consensys/gnark/backend/groth16/setup/utils"
)

type Evaluations struct {
	G1 struct {
		A, B, VKK []bn254.G1Affine
	}
	G2 struct {
		B []bn254.G2Affine
	}
}

type Contribution struct {
	Parameters struct {
		G1 struct {
			Delta bn254.G1Affine
			L, Z  []bn254.G1Affine
		}
		G2 struct {
			Delta bn254.G2Affine
		}
	}
	PublicKey utils.PublicKey
	Hash      []byte
}

func (c2 *Contribution) PreparePhase2(c1 *phase1.Contribution, qap *QAP) Evaluations {
	srs := c1.Parameters
	size := len(srs.G1.AlphaTau)
	if size < qap.NConstraints {
		panic("Number of constraints is larger than expected")
	}

	// Prepare Lagrange coefficients of [τ...]₁, [τ...]₂, [ατ...]₁, [βτ...]₁
	var evals Evaluations
	coeffTau1 := utils.LagrangeCoeffsG1(srs.G1.Tau, size)
	coeffTau2 := utils.LagrangeCoeffsG2(srs.G2.Tau, size)
	coeffAlphaTau1 := utils.LagrangeCoeffsG1(srs.G1.AlphaTau, size)
	coeffBetaTau1 := utils.LagrangeCoeffsG1(srs.G1.BetaTau, size)
	evals.G1.A = make([]bn254.G1Affine, qap.NWires)
	evals.G1.B = make([]bn254.G1Affine, qap.NWires)
	evals.G2.B = make([]bn254.G2Affine, qap.NWires)
	for i := 0; i < qap.NWires; i++ {
		evals.G1.A[i].FromJacobian(utils.EvalG1(qap.A[i], coeffTau1[:qap.NConstraints]))
		evals.G1.B[i].FromJacobian(utils.EvalG1(qap.B[i], coeffTau1[:qap.NConstraints]))
		evals.G2.B[i].FromJacobian(utils.EvalG2(qap.B[i], coeffTau2[:qap.NConstraints]))
	}

	// Prepare default contribution
	_, _, g1, g2 := bn254.Generators()
	c2.Parameters.G1.Delta = g1
	c2.Parameters.G2.Delta = g2

	// Build Z in PK as τⁱ(τⁿ - 1)  = τ⁽ⁱ⁺ⁿ⁾ - τⁱ  for i ∈ [0, n-2]
	// τⁱ(τⁿ - 1)  = τ⁽ⁱ⁺ⁿ⁾ - τⁱ  for i ∈ [0, n-2]
	n := len(srs.G1.AlphaTau)
	c2.Parameters.G1.Z = make([]bn254.G1Affine, n)
	for i := 0; i < n-1; i++ {
		c2.Parameters.G1.Z[i].Sub(&srs.G1.Tau[i+n], &srs.G1.Tau[i])
	}
	// this is an extra point that is added for the sake of being compatible with gnark setup
	// evenutally it is multiplied by zero, hence it won't affect the resutl
	c2.Parameters.G1.Z[n-1].Set(&g1)

	// Evaluate L
	nPrivate := qap.NWires - qap.NPublic
	c2.Parameters.G1.L = make([]bn254.G1Affine, nPrivate)
	evals.G1.VKK = make([]bn254.G1Affine, qap.NPublic)
	offset := qap.NPublic
	var bA, aB, C, res *bn254.G1Jac
	for i := 0; i < qap.NWires; i++ {
		bA = utils.EvalG1(qap.A[i], coeffBetaTau1[:qap.NConstraints])
		aB = utils.EvalG1(qap.B[i], coeffAlphaTau1[:qap.NConstraints])
		C = utils.EvalG1(qap.C[i], coeffTau1[:qap.NConstraints])
		res = bA.AddAssign(aB).AddAssign(C)
		if i < qap.NPublic {
			evals.G1.VKK[i].FromJacobian(res)
		} else {
			c2.Parameters.G1.L[i-offset].FromJacobian(res)
		}
	}
	// Set δ public key
	var delta fr.Element
	delta.SetOne()
	c2.PublicKey = utils.GenPublicKey(delta, nil, 1)

	// Hash initial contribution
	c2.Hash = HashContribution(c2)

	return evals
}

func (c *Contribution) Contribute(prev *Contribution) {
	// Sample toxic δ
	var delta, deltaInv fr.Element
	var deltaBI, deltaInvBI big.Int
	delta.SetRandom()
	deltaInv.Inverse(&delta)

	delta.BigInt(&deltaBI)
	deltaInv.BigInt(&deltaInvBI)

	// Set δ public key
	c.PublicKey = utils.GenPublicKey(delta, prev.Hash, 1)

	// Update δ
	c.Parameters.G1.Delta.ScalarMultiplication(&prev.Parameters.G1.Delta, &deltaBI)
	c.Parameters.G2.Delta.ScalarMultiplication(&prev.Parameters.G2.Delta, &deltaBI)

	// Update Z using δ⁻¹
	c.Parameters.G1.Z = make([]bn254.G1Affine, len(prev.Parameters.G1.Z))
	for i := 0; i < len(prev.Parameters.G1.Z); i++ {
		c.Parameters.G1.Z[i].ScalarMultiplication(&prev.Parameters.G1.Z[i], &deltaInvBI)
	}

	// Update Z using δ⁻¹
	c.Parameters.G1.L = make([]bn254.G1Affine, len(prev.Parameters.G1.L))
	for i := 0; i < len(prev.Parameters.G1.L); i++ {
		c.Parameters.G1.L[i].ScalarMultiplication(&prev.Parameters.G1.L[i], &deltaInvBI)
	}

	// 4. Hash contribution
	c.Hash = HashContribution(c)
}

func HashContribution(c *Contribution) []byte {
	sha := sha256.New()
	// Hash contribution
	toEncode := []interface{}{
		&c.PublicKey.SG,
		&c.PublicKey.SXG,
		&c.PublicKey.XR,
		&c.Parameters.G1.Delta,
		c.Parameters.G1.L,
		c.Parameters.G1.Z,
		&c.Parameters.G2.Delta,
	}

	enc := bn254.NewEncoder(sha)
	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			panic(err)
		}
	}
	return sha.Sum(nil)
}
