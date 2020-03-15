package oauth2

import (
	"crypto/rsa"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func getPublicKeyFingerprint(k *rsa.PublicKey) (string, error) {
	p, err := ssh.NewPublicKey(k)
	if err != nil {
		return "", fmt.Errorf("Error creating SSH public key: %w", err)
	}
	return ssh.FingerprintSHA256(p), nil
}
