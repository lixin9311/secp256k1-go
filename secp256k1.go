package secp256k1

import (
	"crypto/elliptic"
	"math/big"
)

var pool *numPool

func init() {
	pool = &numPool{bns: make([]*big.Int, 0)}
}

func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

type secp256k1Curve struct {
	A       *big.Int
	P       *big.Int // the order of the underlying field
	N       *big.Int // the order of the base point
	B       *big.Int // the constant of the curve equation
	Gx, Gy  *big.Int // (x,y) of the base point
	BitSize int      // the size of the underlying field
	Name    string   // the canonical name of the curve
	params  *elliptic.CurveParams
}

func newsecp256k1() *secp256k1Curve {
	curve := &secp256k1Curve{}
	curve.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	curve.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	curve.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	curve.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	curve.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	curve.Name = "secp256k1"
	curve.BitSize = 256
	// work around for ecdsa
	curve.params = new(elliptic.CurveParams)
	curve.params.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	curve.params.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	curve.params.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	curve.params.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	curve.params.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	curve.params.BitSize = 256
	return curve
}

func (curve *secp256k1Curve) Params() *elliptic.CurveParams {
	// work around for ecdsa
	return curve.params
}

func (curve *secp256k1Curve) IsOnCurve(x, y *big.Int) bool {
	// y² = x³ + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)

	return x3.Cmp(y2) == 0
}

func (curve *secp256k1Curve) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	zinv := new(big.Int).ModInverse(z, curve.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, curve.P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, curve.P)
	return
}

func (curve *secp256k1Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return curve.affineFromJacobian(curve.addJacobian(x1, y1, z1, x2, y2, z2))
}

func (curve *secp256k1Curve) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return x3, y3, z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return x3, y3, z3
	}
	p := curve.P

	// See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3

	// Normalize the points by replacing a = [x1:y1:z1] and b = [x2:y2:z2]
	// by [u1:s1:z1·z2] and [u2:s2:z1·z2]
	// where u1 = x1·z2², s1 = y1·z2³ and u1 = x2·z1², s2 = y2·z1³
	z1z1 := pool.Get().Mul(z1, z1)
	z1z1.Mod(z1z1, p)
	z2z2 := pool.Get().Mul(z2, z2)
	z2z2.Mod(z2z2, p)
	u1 := pool.Get().Mul(x1, z2z2)
	u1.Mod(u1, p)
	u2 := pool.Get().Mul(x2, z1z1)
	u2.Mod(u2, p)

	t := pool.Get().Mul(z2, z2z2)
	t.Mod(t, p)
	s1 := pool.Get().Mul(y1, t)
	s1.Mod(s1, p)

	t.Mul(z1, z1z1)
	t.Mod(t, p)
	s2 := pool.Get().Mul(y2, t)
	s2.Mod(s2, p)

	// Compute x = (2h)²(s²-u1-u2)
	// where s = (s2-s1)/(u2-u1) is the slope of the line through
	// (u1,s1) and (u2,s2). The extra factor 2h = 2(u2-u1) comes from the value of z below.
	// This is also:
	// 4(s2-s1)² - 4h²(u1+u2) = 4(s2-s1)² - 4h³ - 4h²(2u1)
	//                        = r² - j - 2v
	// with the notations below.
	h := pool.Get().Sub(u2, u1)
	xEqual := h.Sign() == 0

	t.Add(h, h)
	// i = 4h²
	i := pool.Get().Mul(t, t)
	i.Mod(i, p)
	// j = 4h³
	j := pool.Get().Mul(h, i)
	j.Mod(j, p)

	t.Sub(s2, s1)
	yEqual := t.Sign() == 0
	if xEqual && yEqual {
		return curve.doubleJacobian(x1, y1, z1)
	}
	r := pool.Get().Add(t, t)

	v := pool.Get().Mul(u1, i)
	v.Mod(v, p)

	// t4 = 4(s2-s1)²
	t4 := pool.Get().Mul(r, r)
	t4.Mod(t4, p)
	t.Add(v, v)
	t6 := pool.Get().Sub(t4, j)
	x3.Sub(t6, t)

	// Set y = -(2h)³(s1 + s*(x/4h²-u1))
	// This is also
	// y = - 2·s1·j - (s2-s1)(2x - 2i·u1) = r(v-x) - 2·s1·j
	t.Sub(v, x3)  // t7
	t4.Mul(s1, j) // t8
	t4.Mod(t4, p)
	t6.Add(t4, t4) // t9
	t4.Mul(r, t)   // t10
	t4.Mod(t4, p)
	y3.Sub(t4, t6)

	// Set z = 2(u2-u1)·z1·z2 = 2h·z1·z2
	t.Add(z1, z2) // t11
	t4.Mul(t, t)  // t12
	t4.Mod(t4, p)
	t.Sub(t4, z1z1) // t13
	t4.Sub(t, z2z2) // t14
	z3.Mul(t4, h)
	z3.Mod(z3, p)

	pool.Put(z1z1)
	pool.Put(z2z2)
	pool.Put(u1)
	pool.Put(u2)
	pool.Put(t)
	pool.Put(s1)
	pool.Put(s2)
	pool.Put(h)
	pool.Put(i)
	pool.Put(j)
	pool.Put(r)
	pool.Put(v)
	pool.Put(t4)
	pool.Put(t6)

	return x3, y3, z3
}

func (curve *secp256k1Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	return curve.affineFromJacobian(curve.doubleJacobian(x1, y1, z1))
}

func (curve *secp256k1Curve) doubleJacobian(x, y, z *big.Int) (*big.Int, *big.Int, *big.Int) {
	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z.Sign() == 0 {
		return x3, y3, z3
	}
	p := curve.P
	A := pool.Get().Mul(x, x)
	A.Mod(A, p)
	B := pool.Get().Mul(y, y)
	B.Mod(B, p)
	C := pool.Get().Mul(B, B)
	C.Mod(C, p)

	t := pool.Get().Add(x, B)
	t2 := pool.Get().Mul(t, t)
	t2.Mod(t2, p)
	t.Sub(t2, A)
	t2.Sub(t, C)
	d := pool.Get().Add(t2, t2)
	t.Add(A, A)
	e := pool.Get().Add(t, A)
	f := pool.Get().Mul(e, e)
	f.Mod(f, p)

	t.Add(d, d)
	x3.Sub(f, t)

	t.Add(C, C)
	t2.Add(t, t)
	t.Add(t2, t2)
	y3.Sub(d, x3)
	t2.Mul(e, y3)
	t2.Mod(t2, p)
	y3.Sub(t2, t)

	t.Mul(y, z)
	t.Mod(t, p)
	z3.Add(t, t)

	pool.Put(A)
	pool.Put(B)
	pool.Put(C)
	pool.Put(t)
	pool.Put(t2)
	pool.Put(d)
	pool.Put(e)
	pool.Put(f)

	return x3, y3, z3
}

func (curve *secp256k1Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	Bz := new(big.Int).SetInt64(1)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)

	for _, byte := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = curve.doubleJacobian(x, y, z)
			if byte&0x80 == 0x80 {
				x, y, z = curve.addJacobian(Bx, By, Bz, x, y, z)
			}
			byte <<= 1
		}
	}

	return curve.affineFromJacobian(x, y, z)
}

// ScalarBaseMult returns k*G, where G is the base point of the group
// and k is an integer in big-endian form.
func (curve *secp256k1Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}
