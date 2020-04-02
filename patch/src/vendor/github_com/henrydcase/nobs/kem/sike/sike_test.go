package sike

import (
	"testing"

	"bufio"
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"strings"

	"fmt"

	rand "crypto/rand"
	. "github_com/henrydcase/nobs/dh/sidh"
)

const (
	PkB = "7C55E268665504B9A11A1B30B4363A4957960AD015A7B74DF39FB0141A95CC51A4BEBBB48452EF0C881220D68CB5FF904C0549F05F06BF49A520E684DD610A7E121B420C751B789BDCDB8B6EC136BA0CE74EB6904906057EA7343839EA35FAF2C3D7BE76C81DCA4DF0850CE5F111FF9FF97242EC5520310D7F90A004BACFD75408CBFE8948232A9CCF035136DE3691D9BEF110C3081AADF0D2328CE2CC94998D8AE94D6575083FAFA045F50201FCE841D01C214CC8BBEFCC701484215EA70518204C76A0DA89BEAF0B066F6FD9E78A2C908CF0AFF74E0B55477190F918397F0CF3A537B7911DA846196AD914114A15C2F3C1062D78B19D23348C3D3D4A9C2B2018B382CC44544DA2FA263EB6212D2D13F254216DE002D4AEA55C75C5349A681D7A809BCC29C4CAE1168AC790321FF7429FAAC2FC09465F93E10B9DD970901A1B1D045DDAC9D7B901E00F29AA9F2C87C8EF848E80B7B290ECF85D6BB4C7E975A939A7AFB63069F900A75C9B7B71C2E7472C21A87AB604B6372D4EBEC5974A711281A819636D8FA3E6608F2B81F35599BBB4A1EB5CBD8F743587550F8CE3A809F5C9C399DD52B2D15F217A36F3218C772FD4E67F67D526DEBE1D31FEC4634927A873A1A6CFE55FF1E35AB72EBBD22E3CDD9D2640813345015BB6BD25A6977D0391D4D78998DD178155FEBF247BED3A9F83EAF3346BA90098B908B2359B60491C94330626709D235D1CFB7C87DCA779CFBA23DA280DC06FAEA0FDB3773B0C6391F889D803B7C04AC6AB27375B440336789823176C57"
	PrB = "00010203040506070809000102030405060708090001020304050607080901028626ED79D451140800E03B59B956F8210E556067407D13DC90FA9E8B872BFB8FAB0A7289852106E40538D3575C500201"
)

var params = Params(FP_751)

type MultiIdTestingFunc func(*testing.T, uint8)

func Do(f MultiIdTestingFunc, t *testing.T) {
	for id, val := range tdata {
		params = Params(id)
		fmt.Printf("\tTesting: %s\n", val.name)
		f(t, id)
	}
}

var tdata = map[uint8]struct {
	name    string
	KatFile string
	PkB     string
	PrB     string
}{
	FP_503: {
		"P-503",
		"../../etc/PQCkemKAT_434.rsp",
		"F11CF893CE4F794216B11A75B0B2981F8DB3FC8550A75C86DB2279FD4CB445E2F4D21F7380570832963F1445AB898267EC1B84196CAC1A84566D7C4D334505C5AB98D638B2E1A5766F5F716FDF1177AB864D2E2CE10BF8DC3D0A3CAFA05B587D746F5CC78E32F283C035886A96698BDCF0F2CAE0B5D4B9C725A3EB2EA13AA43AEC99488962F8B9A5038DD655C0237023CF21002E3E19B1A993C9118DDC74A07B4F9585C0BCEA6E401A384C4F411A5A6E97DA4E53DA6C8F39F62304F201EC93EDFA76FDA6CE557C4389D5ACE744ED5578A391B6AF01F00F93F4EC7CE41F5C5D1FB11D367C0F2CEB4DD9A92BD8948D777F4285EEBB0870C9C39BD0523804A9FDDFCDE61810D8B958E172702EB97D10A98E9FDDFBE1FC2146230AA26B7FFF48B70ECFDBEF9E7CBBCC12308992FDEF8CA0CD9F0A387F1B68D661A46C37D7FAB9A4ECDE63BEF0A3D7732CA7A8E18C88EBEDF546E842E27CC04FA78A8C03DF22A747E2D627FC9EB3FD8A57337BE759D1957C1D31FCA3FEE6D171192B0C",
		"9BC5315580207C6C16DCF3A30C48DAF278DE12E8C27DF6735A4D0A8A41C4F666854E9B13673071CEB2FD61DEF9A850C211E7C50071B1DD0D"},
	FP_751: {
		"P-751",
		"../../etc/PQCkemKAT_644.rsp",
		"7C55E268665504B9A11A1B30B4363A4957960AD015A7B74DF39FB0141A95CC51A4BEBBB48452EF0C881220D68CB5FF904C0549F05F06BF49A520E684DD610A7E121B420C751B789BDCDB8B6EC136BA0CE74EB6904906057EA7343839EA35FAF2C3D7BE76C81DCA4DF0850CE5F111FF9FF97242EC5520310D7F90A004BACFD75408CBFE8948232A9CCF035136DE3691D9BEF110C3081AADF0D2328CE2CC94998D8AE94D6575083FAFA045F50201FCE841D01C214CC8BBEFCC701484215EA70518204C76A0DA89BEAF0B066F6FD9E78A2C908CF0AFF74E0B55477190F918397F0CF3A537B7911DA846196AD914114A15C2F3C1062D78B19D23348C3D3D4A9C2B2018B382CC44544DA2FA263EB6212D2D13F254216DE002D4AEA55C75C5349A681D7A809BCC29C4CAE1168AC790321FF7429FAAC2FC09465F93E10B9DD970901A1B1D045DDAC9D7B901E00F29AA9F2C87C8EF848E80B7B290ECF85D6BB4C7E975A939A7AFB63069F900A75C9B7B71C2E7472C21A87AB604B6372D4EBEC5974A711281A819636D8FA3E6608F2B81F35599BBB4A1EB5CBD8F743587550F8CE3A809F5C9C399DD52B2D15F217A36F3218C772FD4E67F67D526DEBE1D31FEC4634927A873A1A6CFE55FF1E35AB72EBBD22E3CDD9D2640813345015BB6BD25A6977D0391D4D78998DD178155FEBF247BED3A9F83EAF3346BA90098B908B2359B60491C94330626709D235D1CFB7C87DCA779CFBA23DA280DC06FAEA0FDB3773B0C6391F889D803B7C04AC6AB27375B440336789823176C57",
		"00010203040506070809000102030405060708090001020304050607080901028626ED79D451140800E03B59B956F8210E556067407D13DC90FA9E8B872BFB8FAB0A7289852106E40538D3575C500201"},
}

// Fail if err !=nil. Display msg as an error message
func checkErr(t testing.TB, err error, msg string) {
	if err != nil {
		t.Errorf("%s [%s]", msg, err)
	}
}

// Encrypt, Decrypt, check if input/output plaintext is the same
func testPKERoundTrip(t *testing.T, id uint8) {
	// Message to be encrypted
	var params = Params(id)
	var msg = make([]byte, params.MsgLen)
	for i, _ := range msg {
		msg[i] = byte(i)
	}

	// Import keys
	pkB := NewPublicKey(params.Id, KeyVariant_SIKE)
	skB := NewPrivateKey(params.Id, KeyVariant_SIKE)
	pk_hex, err := hex.DecodeString(tdata[id].PkB)
	if err != nil {
		t.Fatal(err)
	}
	sk_hex, err := hex.DecodeString(tdata[id].PrB)
	if err != nil {
		t.Fatal(err)
	}
	if pkB.Import(pk_hex) != nil || skB.Import(sk_hex) != nil {
		t.Error("Import")
	}

	ct, err := Encrypt(rand.Reader, pkB, msg[:])
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(skB, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt[:], msg[:]) {
		t.Errorf("Decryption failed \n got : %X\n exp : %X", pt, msg)
	}
}

// Generate key and check if can encrypt
func testPKEKeyGeneration(t *testing.T, id uint8) {
	// Message to be encrypted
	var params = Params(id)
	var msg = make([]byte, params.MsgLen)
	var err error
	for i, _ := range msg {
		msg[i] = byte(i)
	}

	sk := NewPrivateKey(id, KeyVariant_SIKE)
	err = sk.Generate(rand.Reader)
	checkErr(t, err, "PEK key generation")
	pk := sk.GeneratePublicKey()

	// Try to encrypt
	ct, err := Encrypt(rand.Reader, pk, msg[:])
	checkErr(t, err, "PEK encryption")
	pt, err := Decrypt(sk, ct)
	checkErr(t, err, "PEK key decryption")

	if !bytes.Equal(pt[:], msg[:]) {
		t.Fatalf("Decryption failed \n got : %X\n exp : %X", pt, msg)
	}
}

func testNegativePKE(t *testing.T, id uint8) {
	var msg [40]byte
	var err error
	var params = Params(id)

	// Generate key
	sk := NewPrivateKey(params.Id, KeyVariant_SIKE)
	err = sk.Generate(rand.Reader)
	checkErr(t, err, "key generation")

	pk := sk.GeneratePublicKey()

	// bytelen(msg) - 1
	ct, err := Encrypt(rand.Reader, pk, msg[:params.KemSize+8-1])
	if err == nil {
		t.Fatal("Error hasn't been returned")
	}
	if ct != nil {
		t.Fatal("Ciphertext must be nil")
	}

	// KemSize - 1
	pt, err := Decrypt(sk, msg[:params.KemSize+8-1])
	if err == nil {
		t.Fatal("Error hasn't been returned")
	}
	if pt != nil {
		t.Fatal("Ciphertext must be nil")
	}
}

func testKEMRoundTrip(t *testing.T, pkB, skB []byte, id uint8) {
	// Import keys
	pk := NewPublicKey(id, KeyVariant_SIKE)
	sk := NewPrivateKey(id, KeyVariant_SIKE)
	if pk.Import(pkB) != nil || sk.Import(skB) != nil {
		t.Error("Import failed")
	}

	ct, ss_e, err := Encapsulate(rand.Reader, pk)
	if err != nil {
		t.Error("Encapsulate failed")
	}

	ss_d, err := Decapsulate(sk, pk, ct)
	if err != nil {
		t.Error("Decapsulate failed")
	}
	if !bytes.Equal(ss_e, ss_d) {
		t.Error("Shared secrets from decapsulation and encapsulation differ")
	}
}

func TestKEMRoundTrip(t *testing.T) {
	for id, val := range tdata {
		fmt.Printf("\tTesting: %s\n", val.name)
		pk, err := hex.DecodeString(tdata[id].PkB)
		checkErr(t, err, "public key B not a number")
		sk, err := hex.DecodeString(tdata[id].PrB)
		checkErr(t, err, "private key B not a number")
		testKEMRoundTrip(t, pk, sk, id)
	}
}

func testKEMKeyGeneration(t *testing.T, id uint8) {
	// Generate key
	sk := NewPrivateKey(id, KeyVariant_SIKE)
	checkErr(t, sk.Generate(rand.Reader), "error: key generation")
	pk := sk.GeneratePublicKey()

	// calculated shared secret
	ct, ss_e, err := Encapsulate(rand.Reader, pk)
	checkErr(t, err, "encapsulation failed")
	ss_d, err := Decapsulate(sk, pk, ct)
	checkErr(t, err, "decapsulation failed")

	if !bytes.Equal(ss_e, ss_d) {
		t.Fatalf("KEM failed \n encapsulated: %X\n decapsulated: %X", ss_d, ss_e)
	}
}

func testNegativeKEM(t *testing.T, id uint8) {
	sk := NewPrivateKey(id, KeyVariant_SIKE)
	checkErr(t, sk.Generate(rand.Reader), "error: key generation")
	pk := sk.GeneratePublicKey()

	ct, ss_e, err := Encapsulate(rand.Reader, pk)
	checkErr(t, err, "pre-requisite for a test failed")

	ct[0] = ct[0] - 1
	ss_d, err := Decapsulate(sk, pk, ct)
	checkErr(t, err, "decapsulation returns error when invalid ciphertext provided")

	if bytes.Equal(ss_e, ss_d) {
		// no idea how this could ever happen, but it would be very bad
		t.Error("critical error")
	}

	// Try encapsulating with SIDH key
	pkSidh := NewPublicKey(params.Id, KeyVariant_SIDH_B)
	prSidh := NewPrivateKey(params.Id, KeyVariant_SIDH_B)
	_, _, err = Encapsulate(rand.Reader, pkSidh)
	if err == nil {
		t.Error("encapsulation accepts SIDH public key")
	}
	// Try decapsulating with SIDH key
	_, err = Decapsulate(prSidh, pk, ct)
	if err == nil {
		t.Error("decapsulation accepts SIDH private key key")
	}
}

// In case invalid ciphertext is provided, SIKE's decapsulation must
// return same (but unpredictable) result for a given key.
func testNegativeKEMSameWrongResult(t *testing.T, id uint8) {
	sk := NewPrivateKey(id, KeyVariant_SIKE)
	checkErr(t, sk.Generate(rand.Reader), "error: key generation")
	pk := sk.GeneratePublicKey()

	ct, encSs, err := Encapsulate(rand.Reader, pk)
	checkErr(t, err, "pre-requisite for a test failed")

	// make ciphertext wrong
	ct[0] = ct[0] - 1
	decSs1, err := Decapsulate(sk, pk, ct)
	checkErr(t, err, "pre-requisite for a test failed")

	// second decapsulation must be done with same, but imported private key
	expSk := sk.Export()

	// creat new private key
	sk = NewPrivateKey(params.Id, KeyVariant_SIKE)
	err = sk.Import(expSk)
	checkErr(t, err, "import failed")

	// try decapsulating again. ss2 must be same as ss1 and different than
	// original plaintext
	decSs2, err := Decapsulate(sk, pk, ct)
	checkErr(t, err, "pre-requisite for a test failed")

	if !bytes.Equal(decSs1, decSs2) {
		t.Error("decapsulation is insecure")
	}

	if bytes.Equal(encSs, decSs1) || bytes.Equal(encSs, decSs2) {
		// this test requires that decapsulation returns wrong result
		t.Errorf("test implementation error")
	}
}

func readAndCheckLine(r *bufio.Reader) []byte {
	// Read next line from buffer
	line, isPrefix, err := r.ReadLine()
	if err != nil || isPrefix {
		panic("Wrong format of input file")
	}

	// Function expects that line is in format "KEY = HEX_VALUE". Get
	// value, which should be a hex string
	hexst := strings.Split(string(line), "=")[1]
	hexst = strings.TrimSpace(hexst)
	// Convert value to byte string
	ret, err := hex.DecodeString(hexst)
	if err != nil {
		panic("Wrong format of input file")
	}
	return ret
}

func testKeygen(pk, sk []byte) bool {
	// Import provided private key
	var prvKey = NewPrivateKey(params.Id, KeyVariant_SIKE)
	if prvKey.Import(sk) != nil {
		panic("sike test: can't load KAT")
	}

	// Generate public key
	pubKey := prvKey.GeneratePublicKey()
	return bytes.Equal(pubKey.Export(), pk)
}

func testDecapsulation(pk, sk, ct, ssExpected []byte) bool {
	var pubKey = NewPublicKey(params.Id, KeyVariant_SIKE)
	var prvKey = NewPrivateKey(params.Id, KeyVariant_SIKE)
	if pubKey.Import(pk) != nil || prvKey.Import(sk) != nil {
		panic("sike test: can't load KAT")
	}

	ssGot, err := Decapsulate(prvKey, pubKey, ct)
	if err != nil {
		panic("sike test: can't perform decapsulation KAT")
	}

	if err != nil {
		return false
	}
	return bytes.Equal(ssGot, ssExpected)
}

func testSIKE_KAT(t *testing.T, id uint8) {
	f, err := os.Open(tdata[id].KatFile)
	if err != nil {
		t.Fatal(err)
	}

	r := bufio.NewReader(f)
	for {
		line, isPrefix, err := r.ReadLine()
		if err != nil || isPrefix {
			if err == io.EOF {
				break
			} else {
				t.Fatal(err)
			}
		}
		if len(strings.TrimSpace(string(line))) == 0 || line[0] == '#' {
			continue
		}

		// count
		count := strings.Split(string(line), "=")[1]
		// seed
		_ = readAndCheckLine(r)
		// pk
		pk := readAndCheckLine(r)
		// sk (secret key in test vector is concatenation of
		// MSG + SECRET_BOB_KEY + PUBLIC_BOB_KEY. We use only MSG+SECRET_BOB_KEY
		sk := readAndCheckLine(r)
		sk = sk[:params.MsgLen+uint(params.B.SecretByteLen)]
		// ct
		ct := readAndCheckLine(r)
		// ss
		ss := readAndCheckLine(r)

		if !testKeygen(pk, sk) {
			t.Fatalf("KAT keygen form private failed at %s\n", count)
		}

		if !testDecapsulation(pk, sk, ct, ss) {
			t.Fatalf("KAT decapsulation failed at %s\n", count)
		}

		// aditionally test roundtrip with a keypair
		testKEMRoundTrip(t, pk, sk, id)
	}
}

// Interface to "testing"
func TestPKEKeyGeneration(t *testing.T)           { Do(testPKEKeyGeneration, t) }
func TestPKERoundTrip(t *testing.T)               { Do(testPKERoundTrip, t) }
func TestNegativePKE(t *testing.T)                { Do(testNegativePKE, t) }
func TestKEMKeyGeneration(t *testing.T)           { Do(testKEMKeyGeneration, t) }
func TestNegativeKEM(t *testing.T)                { Do(testNegativeKEM, t) }
func TestSIKE_KAT(t *testing.T)                   { Do(testSIKE_KAT, t) }
func TestNegativeKEMSameWrongResult(t *testing.T) { Do(testNegativeKEMSameWrongResult, t) }
