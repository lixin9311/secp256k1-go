package secp256k1

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestCurveCalculation(t *testing.T) {
	t.Log("Testing the basic calculation of the curve...")
	secp256k1 := newsecp256k1()
	b, _ := big.NewInt(0).SetString("AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522", 16)
	k, p := secp256k1.ScalarBaseMult(b.Bytes())

	expectedK, _ := big.NewInt(0).SetString("23960696573610029253367988531088137163395307586261939660421638862381187549638", 10)
	expectedP, _ := big.NewInt(0).SetString("5176714262835066281222529495396963740342889891785920566957581938958806065714", 10)
	if k.Cmp(expectedK) != 0 || p.Cmp(expectedP) != 0 {
		t.Log("Acquired Values:", k, p)
		t.Log("Expected Values: 23960696573610029253367988531088137163395307586261939660421638862381187549638 5176714262835066281222529495396963740342889891785920566957581938958806065714")
		t.Log("Results did not match!")
		t.FailNow()
	}
}

func BenchmarkScalarBaseMult(b *testing.B) {
	b.ResetTimer()
	secp256k1 := newsecp256k1()
	num, _ := big.NewInt(0).SetString("AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522", 16)
	b.ReportAllocs()
	b.StartTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			secp256k1.ScalarBaseMult(num.Bytes())
		}
	})
}

func TestCurveECDSA(t *testing.T) {
	t.Log("Testing ECDSA from go stdlib using the curve...")
	secp256k1 := newsecp256k1()
	priv, err := ecdsa.GenerateKey(secp256k1, rand.Reader)
	if err != nil {
		t.Fatal("Failed to generate key from the curve:", err)
	}
	text := []byte("Hello secp256k1")
	hash := sha3.New256()
	hashed := hash.Sum(text[:])
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Fatal("Failed to sign the data using the curve:", err)
	}
	// should be ok
	if !ecdsa.Verify(&priv.PublicKey, hashed, r, s) {
		t.Fatal("Failed to verify the signed data using the curve:", err)
	}
	hashed[0] = 1
	if ecdsa.Verify(&priv.PublicKey, hashed, r, s) {
		t.Fatal("Failed to verify the manipulated signed data using the curve:", err)
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	b.ResetTimer()
	secp256k1 := newsecp256k1()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ecdsa.GenerateKey(secp256k1, rand.Reader)
		}
	})
}

func BenchmarkSign(b *testing.B) {
	b.ResetTimer()
	secp256k1 := newsecp256k1()
	hashed := []byte("testing")
	priv, _ := ecdsa.GenerateKey(secp256k1, rand.Reader)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _ = ecdsa.Sign(rand.Reader, priv, hashed)
		}
	})
}

func BenchmarkVerify(b *testing.B) {
	b.ResetTimer()
	secp256k1 := newsecp256k1()
	hashed := []byte("testing")
	priv, _ := ecdsa.GenerateKey(secp256k1, rand.Reader)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, hashed)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ecdsa.Verify(&priv.PublicKey, hashed, r, s)
		}
	})
}
