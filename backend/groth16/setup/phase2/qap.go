package phase2

import (
	"encoding/binary"
	"os"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type QAP struct {
	NConstraints, NWires, NPublic int
	A, B, C                       [][]fr.Element
}

func (qap *QAP) Load(path string) {
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// Read NConstraints, NWires, NPublic
	var nc, nw, np uint32
	binary.Read(file, binary.LittleEndian, &nc)
	binary.Read(file, binary.LittleEndian, &nw)
	binary.Read(file, binary.LittleEndian, &np)
	qap.NConstraints = int(nc)
	qap.NWires = int(nw)
	qap.NPublic = int(np)

	// Initialize A, B, C
	qap.A = make([][]fr.Element, qap.NWires)
	qap.B = make([][]fr.Element, qap.NWires)
	qap.C = make([][]fr.Element, qap.NWires)

	// Read A, B, C
	dec := curve.NewDecoder(file)
	for i := 0; i < int(qap.NWires); i++ {
		qap.A[i] = make([]fr.Element, qap.NConstraints)
		qap.B[i] = make([]fr.Element, qap.NConstraints)
		qap.C[i] = make([]fr.Element, qap.NConstraints)

		err = dec.Decode(&qap.A[i])
		if err != nil {
			panic(err)
		}
		err = dec.Decode(&qap.B[i])
		if err != nil {
			panic(err)
		}
		err = dec.Decode(&qap.C[i])
		if err != nil {
			panic(err)
		}
	}
}
