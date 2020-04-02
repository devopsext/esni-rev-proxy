// +build amd64,!noasm

package p503

import (
	. "github_com/cloudflare/sidh/internal/isogeny"
	cpu "github_com/cloudflare/sidh/internal/utils"
	"reflect"
	"testing"
	"testing/quick"
)

type OptimFlag uint

const (
	// Indicates that optimisation which uses MUL instruction should be used
	kUse_MUL OptimFlag = 1 << 0
	// Indicates that optimisation which uses MULX instruction should be used
	kUse_MULX = 1 << 1
	// Indicates that optimisation which uses MULX, ADOX and ADCX instructions should be used
	kUse_MULXandADxX = 1 << 2
)

func resetCpuFeatures() {
	HasBMI2 = cpu.X86.HasBMI2
	HasADXandBMI2 = cpu.X86.HasBMI2 && cpu.X86.HasADX
}

// Utility function used for testing Mul implementations. Tests caller provided
// mulFunc against mul()
func testMul(t *testing.T, f1, f2 OptimFlag) {
	doMulTest := func(multiplier, multiplicant FpElement) bool {
		defer resetCpuFeatures()
		var resMulRef, resMulOptim FpElementX2

		// Compute multiplier*multiplicant with first implementation
		HasBMI2 = (kUse_MULX & f1) == kUse_MULX
		HasADXandBMI2 = (kUse_MULXandADxX & f1) == kUse_MULXandADxX
		fp503Mul(&resMulOptim, &multiplier, &multiplicant)

		// Compute multiplier*multiplicant with second implementation
		HasBMI2 = (kUse_MULX & f2) == kUse_MULX
		HasADXandBMI2 = (kUse_MULXandADxX & f2) == kUse_MULXandADxX
		fp503Mul(&resMulRef, &multiplier, &multiplicant)

		// Compare results
		return reflect.DeepEqual(resMulRef, resMulOptim)
	}

	if err := quick.Check(doMulTest, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

// Utility function used for testing REDC implementations. Tests caller provided
// redcFunc against redc()
func testRedc(t *testing.T, f1, f2 OptimFlag) {
	doRedcTest := func(aRR FpElementX2) bool {
		defer resetCpuFeatures()
		var resRedcF1, resRedcF2 FpElement
		var aRRcpy = aRR

		// Compute redc with first implementation
		HasBMI2 = (kUse_MULX & f1) == kUse_MULX
		HasADXandBMI2 = (kUse_MULXandADxX & f1) == kUse_MULXandADxX
		fp503MontgomeryReduce(&resRedcF1, &aRR)

		// Compute redc with second implementation
		HasBMI2 = (kUse_MULX & f2) == kUse_MULX
		HasADXandBMI2 = (kUse_MULXandADxX & f2) == kUse_MULXandADxX
		fp503MontgomeryReduce(&resRedcF2, &aRRcpy)

		// Compare results
		return reflect.DeepEqual(resRedcF2, resRedcF1)
	}

	if err := quick.Check(doRedcTest, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

// Ensures correctness of implementation of mul operation which uses MULX
func TestMulWithMULX(t *testing.T) {
	defer resetCpuFeatures()
	if !HasBMI2 {
		t.Skip("MULX not supported by the platform")
	}
	testMul(t, kUse_MULX, kUse_MUL)
}

// Ensures correctness of implementation of mul operation which uses MULX and ADOX/ADCX
func TestMulWithMULXADxX(t *testing.T) {
	defer resetCpuFeatures()
	if !HasADXandBMI2 {
		t.Skip("MULX, ADCX and ADOX not supported by the platform")
	}
	testMul(t, kUse_MULXandADxX, kUse_MUL)
}

// Ensures correctness of implementation of mul operation which uses MULX and ADOX/ADCX
func TestMulWithMULXADxXAgainstMULX(t *testing.T) {
	defer resetCpuFeatures()
	if !HasADXandBMI2 {
		t.Skip("MULX, ADCX and ADOX not supported by the platform")
	}
	testMul(t, kUse_MULX, kUse_MULXandADxX)
}

// Ensures correctness of Montgomery reduction implementation which uses MULX
func TestRedcWithMULX(t *testing.T) {
	defer resetCpuFeatures()
	if !HasBMI2 {
		t.Skip("MULX not supported by the platform")
	}
	testRedc(t, kUse_MULX, kUse_MUL)
}

// Ensures correctness of Montgomery reduction implementation which uses MULX
// and ADCX/ADOX.
func TestRedcWithMULXADxX(t *testing.T) {
	defer resetCpuFeatures()
	if !HasADXandBMI2 {
		t.Skip("MULX, ADCX and ADOX not supported by the platform")
	}
	testRedc(t, kUse_MULXandADxX, kUse_MUL)
}

// Ensures correctness of Montgomery reduction implementation which uses MULX
// and ADCX/ADOX.
func TestRedcWithMULXADxXAgainstMULX(t *testing.T) {
	defer resetCpuFeatures()
	if !HasADXandBMI2 {
		t.Skip("MULX, ADCX and ADOX not supported by the platform")
	}
	testRedc(t, kUse_MULXandADxX, kUse_MULX)
}
