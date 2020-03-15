package oauth2

import (
	"crypto/rsa"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type jwtSigner struct {
	privateKey          *rsa.PrivateKey
	publicKey           *rsa.PublicKey
	pubKeyFingerprint   *string
	pubKeyFingerprintMu *sync.RWMutex
}

func (j jwtSigner) getPublicKeyFingerprint() (string, error) {
	j.pubKeyFingerprintMu.RLock()
	if j.pubKeyFingerprint != nil {
		j.pubKeyFingerprintMu.RUnlock()
		return *j.pubKeyFingerprint, nil
	}
	j.pubKeyFingerprintMu.RUnlock()
	j.pubKeyFingerprintMu.Lock()
	defer j.pubKeyFingerprintMu.Unlock()
	p, err := ssh.NewPublicKey(j.publicKey)
	if err != nil {
		return "", errors.Wrap(err, "Error creating SSH public key")
	}
	fingerprint := ssh.FingerprintSHA256(p)
	j.pubKeyFingerprint = &fingerprint
	return *j.pubKeyFingerprint, nil
}
