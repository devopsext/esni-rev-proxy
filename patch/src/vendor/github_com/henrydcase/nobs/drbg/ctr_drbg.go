// This is initial implementation of CTR_DRBG with AES-256. Code is tested
// and functionaly correct. Nevertheless it will be changed
//
// TODO: Following things still need to be done
// * Add other AES key lengts
// * Validate sizes from table 3 of SP800-90A
// * Improve reseeding so that code returns an error when reseed is needed
// * Add case with derivation function (maybe)
// * Code cleanup
// * Implement benchmark
// * Add rest of the test vectors from CAVP

package drbg

import (
	"crypto/aes"
)

// Constants below correspond to AES-256, which is currently
// the only block cipher supported.
const (
	BlockLen = 16
	KeyLen   = 32
	SeedLen  = BlockLen + KeyLen
)

type CtrDrbg struct {
	v          []byte
	key        []byte
	counter    uint
	strength   uint
	resistance bool
}

func NewCtrDrbg() *CtrDrbg {
	var c = new(CtrDrbg)
	return c
}

func (c *CtrDrbg) inc() {
	for i := BlockLen - 1; i >= 0; i-- {
		if c.v[i] == 0xff {
			c.v[i] = 0x00
		} else {
			c.v[i]++
			break
		}
	}
}

func (c *CtrDrbg) Init(entropy, personalization []byte) bool {
	var lsz int
	var seedBuf [SeedLen]byte

	// Minimum entropy input (SP800-90A, 10.2.1)
	if len(entropy) < int(c.strength/8) {
		return false
	}

	// Security strength for AES-256 as per SP800-57, 5.6.1
	c.strength = 256

	lsz = len(entropy)
	if lsz > SeedLen {
		lsz = SeedLen
	}
	copy(seedBuf[:], entropy[:lsz])

	lsz = len(personalization)
	if lsz > SeedLen {
		lsz = SeedLen
	}

	for i := 0; i < lsz; i++ {
		seedBuf[i] ^= personalization[i]
	}

	c.key = make([]byte, KeyLen)
	c.v = make([]byte, BlockLen)
	c.update(seedBuf[:])
	c.counter = 1
	return true

}
func (c *CtrDrbg) update(data []byte) {
	var buf [3 * BlockLen]byte

	if len(data) != SeedLen {
		// OZAPTF: panic?
		panic("Provided data is not equal to strength/8")
	}

	for i := 0; i < 3*BlockLen; i += BlockLen {
		c.inc()
		// Ignore error => NewCipher returns error when c.key has unexpected size
		encBlock, _ := aes.NewCipher(c.key)
		encBlock.Encrypt(buf[i:], c.v)
	}

	for i := 0; i < len(buf); i++ {
		buf[i] ^= data[i]
	}

	copy(c.key, buf[:KeyLen])
	copy(c.v, buf[KeyLen:])
}

func (c *CtrDrbg) Reseed(entropy, data []byte) {
	var seedBuf [SeedLen]byte
	var lsz int

	lsz = len(entropy)
	if lsz > SeedLen {
		lsz = SeedLen
	}
	copy(seedBuf[:], entropy[:lsz])

	lsz = len(data)
	if lsz > SeedLen {
		lsz = SeedLen
	}

	for i := 0; i < lsz; i++ {
		seedBuf[i] ^= data[i]
	}

	c.update(seedBuf[:])
	c.counter = 1
}

func (c *CtrDrbg) Read(b, ad []byte) (n int, err error) {
	var seedBuf [SeedLen]byte
	// TODO: check reseed_counter > reseed_interval

	if len(ad) > 0 {
		// pad additional data with zeros if needed
		copy(seedBuf[:], ad)
		c.update(seedBuf[:])
	}

	// OZAPTF: would be better not need to allocate that
	buf := make([]byte, ((len(b)+BlockLen)/BlockLen)*BlockLen)
	for i := 0; i < len(b); i += BlockLen {
		c.inc()
		// Ignore error => NewCipher returns error when c.key has unexpected size
		encBlock, _ := aes.NewCipher(c.key)
		encBlock.Encrypt(buf[i:], c.v)
	}

	copy(b, buf[:len(b)])
	c.update(seedBuf[:])
	c.counter += 1
	return len(b), nil
}
