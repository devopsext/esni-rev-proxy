package drbg

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func S2H(s string) []byte {
	hex, e := hex.DecodeString(s)
	if e != nil {
		panic("Can't import private key")
	}
	return hex
}

func TestNominal(t *testing.T) {
	var entropy [16]byte
	var data [48]byte

	c := NewCtrDrbg()
	if !c.Init(entropy[:], nil) {
		t.FailNow()
	}

	c.Read(entropy[0:16], data[:])

	exp := S2H("16BA361FA14563FB1E8BCF88932F9FA7")
	if !bytes.Equal(exp, entropy[:]) {
		t.FailNow()
	}
}

// TODO: should parse *.req file from here: https://raw.githubusercontent.com/coruus/nist-testvectors/master/csrc.nist.gov/groups/STM/cavp/documents/drbg/drbgtestvectors/drbgvectors_pr_false/CTR_DRBG.rsp
var vectors = []struct {
	EntropyInput          []byte
	PersonalizationString []byte
	EntropyInputReseed    []byte
	AdditionalInputReseed []byte
	AdditionalInput1      []byte
	AdditionalInput2      []byte
	ReturnedBits          []byte
}{
	// With Reseeding
	{
		S2H("99903165903fea49c2db26ed675e44cc14cb2c1f28b836b203240b02771e831146ffc4335373bb344688c5c950670291"),
		[]byte{},
		S2H("b4ee99fa9e0eddaf4a3612013cd636c4af69177b43eebb3c58a305b9979b68b5cc820504f6c029aad78a5d29c66e84a0"),
		S2H("2d8c5c28b05696e74774eb69a10f01c5fabc62691ddf7848a8004bb5eeb4d2c5febe1aa01f4d557b23d7e9a0e4e90655"),
		S2H("0dc9cde42ac6e856f01a55f219c614de90c659260948db5053d414bab0ec2e13e995120c3eb5aafc25dc4bdcef8ace24"),
		S2H("711be6c035013189f362211889248ca8a3268e63a7eb26836d915810a680ac4a33cd1180811a31a0f44f08db3dd64f91"),
		S2H("11c7a0326ea737baa7a993d510fafee5374e7bbe17ef0e3e29f50fa68aac2124b017d449768491cac06d136d691a4e80785739f9aaedf311bba752a3268cc531"),
	},

	{
		S2H("ffad10100025a879672ff50374b286712f457dd01441d76ac1a1cd15c7390dd93179a2f5920d198bf34a1b76fbc21289"),
		S2H("1d2be6f25e88fa30c4ef42e4d54efd957dec231fa00143ca47580be666a8c143a916c90b3819a0a7ea914e3c9a2e7a3f"),
		S2H("6c1a089cae313363bc76a780139eb4f2f2048b1f6b07896c5c412bff0385440fc43b73facbb79e3a252fa01fe17ab391"),
		[]byte{},
		[]byte{},
		[]byte{},
		S2H("e053c7d4bd9099ef6a99f190a5fd80219437d642006672338da6e0fe73ca4d24ffa51151bfbdac78d8a2f6255046edf57a04626e9977139c6933274299f3bdff"),
	},
}

func TestVector(t *testing.T) {

	for i := range vectors {
		result := make([]byte, len(vectors[i].ReturnedBits))
		c := NewCtrDrbg()
		if !c.Init(vectors[i].EntropyInput[:], vectors[i].PersonalizationString) {
			t.FailNow()
		}

		if len(vectors[i].EntropyInputReseed) > 0 {
			c.Reseed(vectors[i].EntropyInputReseed[:], vectors[i].AdditionalInputReseed[:])
		}
		c.Read(result[:], vectors[i].AdditionalInput1)
		c.Read(result[:], vectors[i].AdditionalInput2)

		if !bytes.Equal(vectors[i].ReturnedBits[:], result[:]) {
			t.FailNow()
		}

	}
}
