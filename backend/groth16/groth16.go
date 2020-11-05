// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package groth16 implements Groth16 zkSNARK workflow (https://eprint.iacr.org/2016/260.pdf)
package groth16

import (
	"io"

	"github.com/consensys/gnark/frontend"
	backend_bls377 "github.com/consensys/gnark/internal/backend/bls377"
	backend_bls381 "github.com/consensys/gnark/internal/backend/bls381"
	backend_bn256 "github.com/consensys/gnark/internal/backend/bn256"
	backend_bw761 "github.com/consensys/gnark/internal/backend/bw761"
	"github.com/consensys/gurvy"

	"github.com/consensys/gnark/backend/r1cs"
	groth16_bls377 "github.com/consensys/gnark/internal/backend/bls377/groth16"
	groth16_bls381 "github.com/consensys/gnark/internal/backend/bls381/groth16"
	groth16_bn256 "github.com/consensys/gnark/internal/backend/bn256/groth16"
	groth16_bw761 "github.com/consensys/gnark/internal/backend/bw761/groth16"
)

// Proof represents a Groth16 proof generated by groth16.Prove
//
// it's underlying implementation is curve specific (see gnark/internal/backend)
type Proof interface {
	io.WriterTo
	io.ReaderFrom
}

// ProvingKey represents a Groth16 ProvingKey
//
// it's underlying implementation is curve specific (see gnark/internal/backend)
type ProvingKey interface {
	io.WriterTo
	io.ReaderFrom
	IsDifferent(interface{}) bool
}

// VerifyingKey represents a Groth16 VerifyingKey
//
// it's underlying implementation is curve specific (see gnark/internal/backend)
type VerifyingKey interface {
	io.WriterTo
	io.ReaderFrom
	IsDifferent(interface{}) bool
}

// Verify runs the groth16.Verify algorithm on provided proof with given solution
func Verify(proof Proof, vk VerifyingKey, solution interface{}) error {
	_solution, err := frontend.ParseWitness(solution)
	if err != nil {
		return err
	}
	switch _proof := proof.(type) {
	case *groth16_bls377.Proof:
		return groth16_bls377.Verify(_proof, vk.(*groth16_bls377.VerifyingKey), _solution)
	case *groth16_bls381.Proof:
		return groth16_bls381.Verify(_proof, vk.(*groth16_bls381.VerifyingKey), _solution)
	case *groth16_bn256.Proof:
		return groth16_bn256.Verify(_proof, vk.(*groth16_bn256.VerifyingKey), _solution)
	case *groth16_bw761.Proof:
		return groth16_bw761.Verify(_proof, vk.(*groth16_bw761.VerifyingKey), _solution)
	default:
		panic("unrecognized R1CS curve type")
	}
}

// Prove generates the proof of knoweldge of a r1cs with solution.
// if force flag is set, Prove ignores R1CS solving error (ie invalid solution) and executes
// the FFTs and MultiExponentiations to compute an (invalid) Proof object
func Prove(r1cs r1cs.R1CS, pk ProvingKey, solution interface{}, force ...bool) (Proof, error) {

	_solution, err := frontend.ParseWitness(solution)

	if err != nil {
		return nil, err
	}

	_force := false
	if len(force) > 0 {
		_force = force[0]
	}

	switch _r1cs := r1cs.(type) {
	case *backend_bls377.R1CS:
		return groth16_bls377.Prove(_r1cs, pk.(*groth16_bls377.ProvingKey), _solution, _force)
	case *backend_bls381.R1CS:
		return groth16_bls381.Prove(_r1cs, pk.(*groth16_bls381.ProvingKey), _solution, _force)
	case *backend_bn256.R1CS:
		return groth16_bn256.Prove(_r1cs, pk.(*groth16_bn256.ProvingKey), _solution, _force)
	case *backend_bw761.R1CS:
		return groth16_bw761.Prove(_r1cs, pk.(*groth16_bw761.ProvingKey), _solution, _force)
	default:
		panic("unrecognized R1CS curve type")
	}
}

// Setup runs groth16.Setup with provided R1CS
func Setup(r1cs r1cs.R1CS) (ProvingKey, VerifyingKey) {

	switch _r1cs := r1cs.(type) {
	case *backend_bls377.R1CS:
		var pk groth16_bls377.ProvingKey
		var vk groth16_bls377.VerifyingKey
		groth16_bls377.Setup(_r1cs, &pk, &vk)
		return &pk, &vk
	case *backend_bls381.R1CS:
		var pk groth16_bls381.ProvingKey
		var vk groth16_bls381.VerifyingKey
		groth16_bls381.Setup(_r1cs, &pk, &vk)
		return &pk, &vk
	case *backend_bn256.R1CS:
		var pk groth16_bn256.ProvingKey
		var vk groth16_bn256.VerifyingKey
		groth16_bn256.Setup(_r1cs, &pk, &vk)
		return &pk, &vk
	case *backend_bw761.R1CS:
		var pk groth16_bw761.ProvingKey
		var vk groth16_bw761.VerifyingKey
		groth16_bw761.Setup(_r1cs, &pk, &vk)
		return &pk, &vk
	default:
		panic("unrecognized R1CS curve type")
	}
}

// DummySetup create a random ProvingKey with provided R1CS
// it doesn't return a VerifyingKey and is use for benchmarking or test purposes only.
func DummySetup(r1cs r1cs.R1CS) ProvingKey {
	switch _r1cs := r1cs.(type) {
	case *backend_bls377.R1CS:
		var pk groth16_bls377.ProvingKey
		groth16_bls377.DummySetup(_r1cs, &pk)
		return &pk
	case *backend_bls381.R1CS:
		var pk groth16_bls381.ProvingKey
		groth16_bls381.DummySetup(_r1cs, &pk)
		return &pk
	case *backend_bn256.R1CS:
		var pk groth16_bn256.ProvingKey
		groth16_bn256.DummySetup(_r1cs, &pk)
		return &pk
	case *backend_bw761.R1CS:
		var pk groth16_bw761.ProvingKey
		groth16_bw761.DummySetup(_r1cs, &pk)
		return &pk
	default:
		panic("unrecognized R1CS curve type")
	}
}

// ReadProvingKey read file at path and attempt to decode it into a ProvingKey object
//
// note that until v1.X.X serialization (schema-less, disk, network, ..) may change
func ReadProvingKey(reader io.Reader, curveID gurvy.ID) (ProvingKey, error) {
	var pk ProvingKey
	switch curveID {
	case gurvy.BN256:
		pk = &groth16_bn256.ProvingKey{}
	case gurvy.BLS377:
		pk = &groth16_bls377.ProvingKey{}
	case gurvy.BLS381:
		pk = &groth16_bls381.ProvingKey{}
	case gurvy.BW761:
		pk = &groth16_bw761.ProvingKey{}
	default:
		panic("not implemented")
	}

	if _, err := pk.ReadFrom(reader); err != nil {
		return nil, err
	}
	return pk, nil
}

// ReadVerifyingKey read file at path and attempt to decode it into a VerifyingKey
//
// note that until v1.X.X serialization (schema-less, disk, network, ..) may change
func ReadVerifyingKey(reader io.Reader, curveID gurvy.ID) (VerifyingKey, error) {
	var vk VerifyingKey
	switch curveID {
	case gurvy.BN256:
		vk = &groth16_bn256.VerifyingKey{}
	case gurvy.BLS377:
		vk = &groth16_bls377.VerifyingKey{}
	case gurvy.BLS381:
		vk = &groth16_bls381.VerifyingKey{}
	case gurvy.BW761:
		vk = &groth16_bw761.VerifyingKey{}
	default:
		panic("not implemented")
	}

	if _, err := vk.ReadFrom(reader); err != nil {
		return nil, err
	}
	return vk, nil
}

// ReadProof will read proof at given path into a curve-typed object
//
// note that until v1.X.X serialization (schema-less, disk, network, ..) may change
func ReadProof(reader io.Reader, curveID gurvy.ID) (Proof, error) {
	var proof Proof
	switch curveID {
	case gurvy.BN256:
		proof = &groth16_bn256.Proof{}
	case gurvy.BLS377:
		proof = &groth16_bls377.Proof{}
	case gurvy.BLS381:
		proof = &groth16_bls381.Proof{}
	case gurvy.BW761:
		proof = &groth16_bw761.Proof{}
	default:
		panic("not implemented")
	}

	if _, err := proof.ReadFrom(reader); err != nil {
		return nil, err
	}
	return proof, nil
}
