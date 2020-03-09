package bls

import (
	"unsafe"
)

// SecretKey

func CastFromSecretKey(in *SecretKey) *Fr {
	return (*Fr)(unsafe.Pointer(in))
}

func CastToSecretKey(in *Fr) *SecretKey {
	return (*SecretKey)(unsafe.Pointer(in))
}

// PublicKey

func CastG1FromPublicKey(in *PublicKey) *G1 {
	if IsSwapG() {
		return (*G1)(unsafe.Pointer(in))
	}
	panic("cannot cast PK to G1")
}

func CastG1ToPublicKey(in *G1) *PublicKey {
	if IsSwapG() {
		return (*PublicKey)(unsafe.Pointer(in))
	}
	panic("cannot cast G1 to PK")
}

func CastG2FromPublicKey(in *PublicKey) *G2 {
	if !IsSwapG() {
		return (*G2)(unsafe.Pointer(in))
	}
	panic("cannot cast PK to G2")
}

func CastG2ToPublicKey(in *G2) *PublicKey {
	if !IsSwapG() {
		return (*PublicKey)(unsafe.Pointer(in))
	}
	panic("cannot cast G2 to PK")
}

// Sign

func CastG1FromSign(in *Sign) *G1 {
	if !IsSwapG() {
		return (*G1)(unsafe.Pointer(in))
	}
	panic("cannot cast Sign to G1")
}

func CastG1ToSign(in *G1) *Sign {
	if !IsSwapG() {
		return (*Sign)(unsafe.Pointer(in))
	}
	panic("cannot cast G1 to Sig")
}

func CastG2FromSign(in *Sign) *G2 {
	if IsSwapG() {
		return (*G2)(unsafe.Pointer(in))
	}
	panic("cannot cast Sign to G2")
}

func CastG2ToSign(in *G2) *Sign {
	if IsSwapG() {
		return (*Sign)(unsafe.Pointer(in))
	}
	panic("cannot cast G2 to Sig")
}
