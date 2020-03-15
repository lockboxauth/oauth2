package oauth2

import (
	"crypto/rsa"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type JWTSigner struct {
	PrivateKey          *rsa.PrivateKey
	PublicKey           *rsa.PublicKey
	PubKeyFingerprint   *string
	PubKeyFingerprintMu *sync.RWMutex
}

func (j JWTSigner) getPublicKeyFingerprint() (string, error) {
	j.PubKeyFingerprintMu.RLock()
	if j.PubKeyFingerprint != nil {
		j.PubKeyFingerprintMu.RUnlock()
		return *j.PubKeyFingerprint, nil
	}
	j.PubKeyFingerprintMu.RUnlock()
	j.PubKeyFingerprintMu.Lock()
	defer j.PubKeyFingerprintMu.Unlock()
	p, err := ssh.NewPublicKey(j.PublicKey)
	if err != nil {
		return "", errors.Wrap(err, "Error creating SSH public key")
	}
	fingerprint := ssh.FingerprintSHA256(p)
	j.PubKeyFingerprint = &fingerprint
	return *j.PubKeyFingerprint, nil
}

func NewJWTSigner(pub *rsa.PublicKey, priv *rsa.PrivateKey) *JWTSigner {
	var mu sync.RWMutex
	return &JWTSigner{
		PrivateKey:          priv,
		PublicKey:           pub,
		PubKeyFingerprintMu: &mu,
	}
}
