package sm3

func rotl32(count uint32, val uint32) uint32 {
	return (val << count) | (val >> (32 - count))
}

// compression
func p0(X uint32) uint32 {
	return X ^ rotl32(9, X) ^ rotl32(17, X)
}

// expansion
func p1(X uint32) uint32 {
	return X ^ rotl32(15, X) ^ rotl32(23, X)
}

func ff1(X uint32, Y uint32, Z uint32) uint32 {
	return (X & Y) | ((X | Y) & Z)
}

func gg1(X uint32, Y uint32, Z uint32) uint32 {
	return (X & Y) ^ ((^X) & Z) // Can be also (Z ^ (X & (Y ^ Z)))
}

func r1(
	A uint32, B *uint32, C uint32, D *uint32, E uint32, F *uint32,
	G uint32, H *uint32, TJ uint32, Wi uint32, Wj uint32) {

	A12 := rotl32(12, A)
	SS1 := rotl32(7, A12+E+TJ)
	TT1 := (A ^ *B ^ C) + *D + (SS1 ^ A12) + Wj
	TT2 := (E ^ *F ^ G) + *H + SS1 + Wi

	*B = rotl32(9, *B)
	*D = TT1
	*F = rotl32(19, *F)
	*H = p0(TT2)
}

func r2(
	A uint32, B *uint32, C uint32, D *uint32, E uint32, F *uint32,
	G uint32, H *uint32, TJ uint32, Wi uint32, Wj uint32) {

	A12 := rotl32(12, A)
	SS1 := rotl32(7, A12+E+TJ)
	TT1 := ff1(A, *B, C) + *D + (SS1 ^ A12) + Wj
	TT2 := gg1(E, *F, G) + *H + SS1 + Wi

	*B = rotl32(9, *B)
	*D = TT1
	*F = rotl32(19, *F)
	*H = p0(TT2)
}

func sm3e(W0 uint32, W7 uint32, W13 uint32, W3 uint32, W10 uint32) uint32 {
	return p1(W0^W7^rotl32(15, W13)) ^ rotl32(7, W3) ^ W10
}

func loadBe32(x []byte) uint32 {
	return uint32(x[3]) | (uint32(x[2]) << 8) | (uint32(x[1]) << 16) | (uint32(x[0]) << 24)
}

func store64Be(val []byte, x uint64) {
	val[0] = byte(x >> 56)
	val[1] = byte(x >> 48)
	val[2] = byte(x >> 40)
	val[3] = byte(x >> 32)
	val[4] = byte(x >> 24)
	val[5] = byte(x >> 16)
	val[6] = byte(x >> 8)
	val[7] = byte(x >> 0)
}

func store32Be(val []byte, x uint32) {
	val[0] = byte(x >> 24)
	val[1] = byte(x >> 16)
	val[2] = byte(x >> 8)
	val[3] = byte(x >> 0)
}

func (d *digest) compress(input []byte, blocks int) {
	A := d.h[0]
	B := d.h[1]
	C := d.h[2]
	D := d.h[3]
	E := d.h[4]
	F := d.h[5]
	G := d.h[6]
	H := d.h[7]

	for i := 0; i < blocks; i++ {
		next64Block := input[i*64:]

		W00 := loadBe32(next64Block[0:])
		W01 := loadBe32(next64Block[4:])
		W02 := loadBe32(next64Block[8:])
		W03 := loadBe32(next64Block[12:])
		W04 := loadBe32(next64Block[16:])
		W05 := loadBe32(next64Block[20:])
		W06 := loadBe32(next64Block[24:])
		W07 := loadBe32(next64Block[28:])
		W08 := loadBe32(next64Block[32:])
		W09 := loadBe32(next64Block[36:])
		W10 := loadBe32(next64Block[40:])
		W11 := loadBe32(next64Block[44:])
		W12 := loadBe32(next64Block[48:])
		W13 := loadBe32(next64Block[52:])
		W14 := loadBe32(next64Block[56:])
		W15 := loadBe32(next64Block[60:])
		r1(A, &B, C, &D, E, &F, G, &H, 0x79CC4519, W00, W00^W04)
		W00 = sm3e(W00, W07, W13, W03, W10)
		r1(D, &A, B, &C, H, &E, F, &G, 0xF3988A32, W01, W01^W05)
		W01 = sm3e(W01, W08, W14, W04, W11)
		r1(C, &D, A, &B, G, &H, E, &F, 0xE7311465, W02, W02^W06)
		W02 = sm3e(W02, W09, W15, W05, W12)
		r1(B, &C, D, &A, F, &G, H, &E, 0xCE6228CB, W03, W03^W07)
		W03 = sm3e(W03, W10, W00, W06, W13)
		r1(A, &B, C, &D, E, &F, G, &H, 0x9CC45197, W04, W04^W08)
		W04 = sm3e(W04, W11, W01, W07, W14)
		r1(D, &A, B, &C, H, &E, F, &G, 0x3988A32F, W05, W05^W09)
		W05 = sm3e(W05, W12, W02, W08, W15)
		r1(C, &D, A, &B, G, &H, E, &F, 0x7311465E, W06, W06^W10)
		W06 = sm3e(W06, W13, W03, W09, W00)
		r1(B, &C, D, &A, F, &G, H, &E, 0xE6228CBC, W07, W07^W11)
		W07 = sm3e(W07, W14, W04, W10, W01)
		r1(A, &B, C, &D, E, &F, G, &H, 0xCC451979, W08, W08^W12)
		W08 = sm3e(W08, W15, W05, W11, W02)
		r1(D, &A, B, &C, H, &E, F, &G, 0x988A32F3, W09, W09^W13)
		W09 = sm3e(W09, W00, W06, W12, W03)
		r1(C, &D, A, &B, G, &H, E, &F, 0x311465E7, W10, W10^W14)
		W10 = sm3e(W10, W01, W07, W13, W04)
		r1(B, &C, D, &A, F, &G, H, &E, 0x6228CBCE, W11, W11^W15)
		W11 = sm3e(W11, W02, W08, W14, W05)
		r1(A, &B, C, &D, E, &F, G, &H, 0xC451979C, W12, W12^W00)
		W12 = sm3e(W12, W03, W09, W15, W06)
		r1(D, &A, B, &C, H, &E, F, &G, 0x88A32F39, W13, W13^W01)
		W13 = sm3e(W13, W04, W10, W00, W07)
		r1(C, &D, A, &B, G, &H, E, &F, 0x11465E73, W14, W14^W02)
		W14 = sm3e(W14, W05, W11, W01, W08)
		r1(B, &C, D, &A, F, &G, H, &E, 0x228CBCE6, W15, W15^W03)
		W15 = sm3e(W15, W06, W12, W02, W09)
		r2(A, &B, C, &D, E, &F, G, &H, 0x9D8A7A87, W00, W00^W04)
		W00 = sm3e(W00, W07, W13, W03, W10)
		r2(D, &A, B, &C, H, &E, F, &G, 0x3B14F50F, W01, W01^W05)
		W01 = sm3e(W01, W08, W14, W04, W11)
		r2(C, &D, A, &B, G, &H, E, &F, 0x7629EA1E, W02, W02^W06)
		W02 = sm3e(W02, W09, W15, W05, W12)
		r2(B, &C, D, &A, F, &G, H, &E, 0xEC53D43C, W03, W03^W07)
		W03 = sm3e(W03, W10, W00, W06, W13)
		r2(A, &B, C, &D, E, &F, G, &H, 0xD8A7A879, W04, W04^W08)
		W04 = sm3e(W04, W11, W01, W07, W14)
		r2(D, &A, B, &C, H, &E, F, &G, 0xB14F50F3, W05, W05^W09)
		W05 = sm3e(W05, W12, W02, W08, W15)
		r2(C, &D, A, &B, G, &H, E, &F, 0x629EA1E7, W06, W06^W10)
		W06 = sm3e(W06, W13, W03, W09, W00)
		r2(B, &C, D, &A, F, &G, H, &E, 0xC53D43CE, W07, W07^W11)
		W07 = sm3e(W07, W14, W04, W10, W01)
		r2(A, &B, C, &D, E, &F, G, &H, 0x8A7A879D, W08, W08^W12)
		W08 = sm3e(W08, W15, W05, W11, W02)
		r2(D, &A, B, &C, H, &E, F, &G, 0x14F50F3B, W09, W09^W13)
		W09 = sm3e(W09, W00, W06, W12, W03)
		r2(C, &D, A, &B, G, &H, E, &F, 0x29EA1E76, W10, W10^W14)
		W10 = sm3e(W10, W01, W07, W13, W04)
		r2(B, &C, D, &A, F, &G, H, &E, 0x53D43CEC, W11, W11^W15)
		W11 = sm3e(W11, W02, W08, W14, W05)
		r2(A, &B, C, &D, E, &F, G, &H, 0xA7A879D8, W12, W12^W00)
		W12 = sm3e(W12, W03, W09, W15, W06)
		r2(D, &A, B, &C, H, &E, F, &G, 0x4F50F3B1, W13, W13^W01)
		W13 = sm3e(W13, W04, W10, W00, W07)
		r2(C, &D, A, &B, G, &H, E, &F, 0x9EA1E762, W14, W14^W02)
		W14 = sm3e(W14, W05, W11, W01, W08)
		r2(B, &C, D, &A, F, &G, H, &E, 0x3D43CEC5, W15, W15^W03)
		W15 = sm3e(W15, W06, W12, W02, W09)
		r2(A, &B, C, &D, E, &F, G, &H, 0x7A879D8A, W00, W00^W04)
		W00 = sm3e(W00, W07, W13, W03, W10)
		r2(D, &A, B, &C, H, &E, F, &G, 0xF50F3B14, W01, W01^W05)
		W01 = sm3e(W01, W08, W14, W04, W11)
		r2(C, &D, A, &B, G, &H, E, &F, 0xEA1E7629, W02, W02^W06)
		W02 = sm3e(W02, W09, W15, W05, W12)
		r2(B, &C, D, &A, F, &G, H, &E, 0xD43CEC53, W03, W03^W07)
		W03 = sm3e(W03, W10, W00, W06, W13)
		r2(A, &B, C, &D, E, &F, G, &H, 0xA879D8A7, W04, W04^W08)
		W04 = sm3e(W04, W11, W01, W07, W14)
		r2(D, &A, B, &C, H, &E, F, &G, 0x50F3B14F, W05, W05^W09)
		W05 = sm3e(W05, W12, W02, W08, W15)
		r2(C, &D, A, &B, G, &H, E, &F, 0xA1E7629E, W06, W06^W10)
		W06 = sm3e(W06, W13, W03, W09, W00)
		r2(B, &C, D, &A, F, &G, H, &E, 0x43CEC53D, W07, W07^W11)
		W07 = sm3e(W07, W14, W04, W10, W01)
		r2(A, &B, C, &D, E, &F, G, &H, 0x879D8A7A, W08, W08^W12)
		W08 = sm3e(W08, W15, W05, W11, W02)
		r2(D, &A, B, &C, H, &E, F, &G, 0x0F3B14F5, W09, W09^W13)
		W09 = sm3e(W09, W00, W06, W12, W03)
		r2(C, &D, A, &B, G, &H, E, &F, 0x1E7629EA, W10, W10^W14)
		W10 = sm3e(W10, W01, W07, W13, W04)
		r2(B, &C, D, &A, F, &G, H, &E, 0x3CEC53D4, W11, W11^W15)
		W11 = sm3e(W11, W02, W08, W14, W05)
		r2(A, &B, C, &D, E, &F, G, &H, 0x79D8A7A8, W12, W12^W00)
		W12 = sm3e(W12, W03, W09, W15, W06)
		r2(D, &A, B, &C, H, &E, F, &G, 0xF3B14F50, W13, W13^W01)
		W13 = sm3e(W13, W04, W10, W00, W07)
		r2(C, &D, A, &B, G, &H, E, &F, 0xE7629EA1, W14, W14^W02)
		W14 = sm3e(W14, W05, W11, W01, W08)
		r2(B, &C, D, &A, F, &G, H, &E, 0xCEC53D43, W15, W15^W03)
		W15 = sm3e(W15, W06, W12, W02, W09)
		r2(A, &B, C, &D, E, &F, G, &H, 0x9D8A7A87, W00, W00^W04)
		W00 = sm3e(W00, W07, W13, W03, W10)
		r2(D, &A, B, &C, H, &E, F, &G, 0x3B14F50F, W01, W01^W05)
		W01 = sm3e(W01, W08, W14, W04, W11)
		r2(C, &D, A, &B, G, &H, E, &F, 0x7629EA1E, W02, W02^W06)
		W02 = sm3e(W02, W09, W15, W05, W12)
		r2(B, &C, D, &A, F, &G, H, &E, 0xEC53D43C, W03, W03^W07)
		W03 = sm3e(W03, W10, W00, W06, W13)
		r2(A, &B, C, &D, E, &F, G, &H, 0xD8A7A879, W04, W04^W08)
		r2(D, &A, B, &C, H, &E, F, &G, 0xB14F50F3, W05, W05^W09)
		r2(C, &D, A, &B, G, &H, E, &F, 0x629EA1E7, W06, W06^W10)
		r2(B, &C, D, &A, F, &G, H, &E, 0xC53D43CE, W07, W07^W11)
		r2(A, &B, C, &D, E, &F, G, &H, 0x8A7A879D, W08, W08^W12)
		r2(D, &A, B, &C, H, &E, F, &G, 0x14F50F3B, W09, W09^W13)
		r2(C, &D, A, &B, G, &H, E, &F, 0x29EA1E76, W10, W10^W14)
		r2(B, &C, D, &A, F, &G, H, &E, 0x53D43CEC, W11, W11^W15)
		r2(A, &B, C, &D, E, &F, G, &H, 0xA7A879D8, W12, W12^W00)
		r2(D, &A, B, &C, H, &E, F, &G, 0x4F50F3B1, W13, W13^W01)
		r2(C, &D, A, &B, G, &H, E, &F, 0x9EA1E762, W14, W14^W02)
		r2(B, &C, D, &A, F, &G, H, &E, 0x3D43CEC5, W15, W15^W03)

		d.h[0] ^= A
		d.h[1] ^= B
		d.h[2] ^= C
		d.h[3] ^= D
		d.h[4] ^= E
		d.h[5] ^= F
		d.h[6] ^= G
		d.h[7] ^= H

		A = d.h[0]
		B = d.h[1]
		C = d.h[2]
		D = d.h[3]
		E = d.h[4]
		F = d.h[5]
		G = d.h[6]
		H = d.h[7]
	}
}
