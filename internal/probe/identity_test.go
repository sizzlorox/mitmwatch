package probe

import "testing"

// The accept list is keyed by Hash, and it is the only way a user can silence a
// finding they know is benign. If the hash moves on its own, the CLI's promise
// that an accepted finding "will not be reported again" becomes a lie and the
// alert returns forever - which is exactly the alarm fatigue the whole design
// is built to avoid.

func TestHashIgnoresVolatileEvidence(t *testing.T) {
	base := Finding{
		Vector: "truststore/young-root", Target: "ESET SSL Filter CA",
		Identity: map[string]string{"sha256": "da01445523252956"},
		Evidence: map[string]string{"age_days": "240", "issued": "2025-12-20"},
	}
	tomorrow := base
	tomorrow.Evidence = map[string]string{"age_days": "241", "issued": "2025-12-20"}

	if base.Hash() != tomorrow.Hash() {
		t.Fatalf("hash changed when only age_days ticked: %s -> %s.\n"+
			"An accept would expire at midnight and the finding would return daily.",
			base.Hash(), tomorrow.Hash())
	}
}

func TestHashIgnoresRotatingSerial(t *testing.T) {
	base := Finding{
		Vector: "tls/private-root", Target: "github.com",
		Identity: map[string]string{"root_subject": "CN=ESET SSL Filter CA"},
		Evidence: map[string]string{"leaf_serial": "01", "issuer_cn": "ESET SSL Filter CA"},
	}
	rotated := base
	rotated.Evidence = map[string]string{"leaf_serial": "02", "issuer_cn": "ESET SSL Filter CA"}

	if base.Hash() != rotated.Hash() {
		t.Fatal("hash changed when only the leaf serial rotated; an interceptor mints " +
			"a fresh leaf on every rotation, so the accept would never hold")
	}
}

// The security property that motivated hashing evidence in the first place must
// survive: accepting one root must not silently accept a different one.
func TestHashDistinguishesDifferentIdentities(t *testing.T) {
	a := Finding{
		Vector: "tls/private-root", Target: "github.com",
		Identity: map[string]string{"root_subject": "CN=Corp Proxy CA"},
	}
	b := a
	b.Identity = map[string]string{"root_subject": "CN=Someone Else CA"}

	if a.Hash() == b.Hash() {
		t.Fatal("two different roots hash the same; accepting one would hide the other")
	}
}

func TestHashIsOrderIndependent(t *testing.T) {
	a := Finding{Vector: "v", Target: "t", Identity: map[string]string{"x": "1", "y": "2"}}
	b := Finding{Vector: "v", Target: "t", Identity: map[string]string{"y": "2", "x": "1"}}
	if a.Hash() != b.Hash() {
		t.Fatal("hash depends on map iteration order")
	}
}

func TestHashSeparatesVectorAndTarget(t *testing.T) {
	sameIdentity := map[string]string{"k": "v"}
	a := Finding{Vector: "tls/private-root", Target: "github.com", Identity: sameIdentity}
	b := Finding{Vector: "tls/private-root", Target: "www.google.com", Identity: sameIdentity}
	c := Finding{Vector: "tls/untrusted-root", Target: "github.com", Identity: sameIdentity}

	if a.Hash() == b.Hash() {
		t.Error("accepting a finding on one host would accept it on another")
	}
	if a.Hash() == c.Hash() {
		t.Error("accepting one vector would accept a different one")
	}
}

// A finding with no identity is identified by vector and target alone. That is
// correct for conditions with only one way to be true - an unreadable trust
// store, a clock that is out - and must stay stable rather than collide.
func TestEmptyIdentityIsStable(t *testing.T) {
	a := Finding{Vector: "clock/drift-major", Target: "network"}
	b := Finding{
		Vector: "clock/drift-major", Target: "network",
		Evidence: map[string]string{"median_drift_sec": "612.4"},
	}
	if a.Hash() != b.Hash() {
		t.Fatal("evidence leaked into the hash of an identity-free finding")
	}
}
