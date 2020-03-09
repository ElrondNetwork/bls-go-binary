package bls

import "testing"

func hasPanicked(f func()) (ret bool) {
	defer func() {
		p := recover()
		ret = p != nil
	}()

	f()
	return
}

func TestConvertPublicKey(t *testing.T) {
	_ = Init(BLS12_381)
	var sec SecretKey

	sec.SetByCSPRNG()
	t.Logf("sec:%s", sec.SerializeToHexStr())

	pub := sec.GetPublicKey()
	t.Logf("pub:%s", pub.SerializeToHexStr())

	isSwap := IsSwapG()

	var pub2 *PublicKey
	var g1 *G1
	var g2 *G2

	g1ConvPanicked := hasPanicked(func() {
		g1 = CastG1FromPublicKey(pub)
	})

	g2ConvPanicked := hasPanicked(func() {
		g2 = CastG2FromPublicKey(pub)
	})

	switch {
	case isSwap && !g1ConvPanicked:
		pub2 = CastG1ToPublicKey(g1)
	case !isSwap && !g2ConvPanicked:
		pub2 = CastG2ToPublicKey(g2)
	default:
		t.Errorf("unexpected isSwap=%v, g1ConvPanicked=%v, g2ConvPanicked=%v",
			isSwap, g1ConvPanicked, g2ConvPanicked)
	}

	if !pub.IsEqual(pub2) {
		t.Error("public keys not equal")
	}
	t.Logf("pub2:%s", pub2.SerializeToHexStr())
}

func TestConvertSecretKey(t *testing.T) {
	_ = Init(BLS12_381)
	sec := &SecretKey{}

	sec.SetByCSPRNG()
	t.Logf("sec:%s", sec.SerializeToHexStr())

	fr := CastFromSecretKey(sec)
	sec2 := CastToSecretKey(fr)

	if !sec.IsEqual(sec2) {
		t.Error("secret keys not equal")
	}
	t.Logf("sec2:%s", sec2.SerializeToHexStr())
}

func TestConversions(t *testing.T) {
	_ = Init(BLS12_381)
	var sec SecretKey

	sec.SetByCSPRNG()
	t.Logf("sec:%s", sec.SerializeToHexStr())

	isSwap := IsSwapG()

	message := "message to sign"
	sig := sec.Sign(message)
	t.Logf("sig:%s", sig.SerializeToHexStr())

	var sig2 *Sign
	var g1 *G1
	var g2 *G2

	g1ConvPanicked := hasPanicked(func() {
		g1 = CastG1FromSign(sig)
	})

	g2ConvPanicked := hasPanicked(func() {
		g2 = CastG2FromSign(sig)
	})

	switch {
	case !isSwap && !g1ConvPanicked:
		sig2 = CastG1ToSign(g1)
	case isSwap && !g2ConvPanicked:
		sig2 = CastG2ToSign(g2)
	default:
		t.Errorf("unexpected isSwap=%v, g1ConvPanicked=%v, g2ConvPanicked=%v",
			isSwap, g1ConvPanicked, g2ConvPanicked)
	}

	if !sig.IsEqual(sig2) {
		t.Error("signatures not equal")
	}
	t.Logf("sig2:%s", sig2.SerializeToHexStr())
}
