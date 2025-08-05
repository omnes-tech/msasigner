package fireblocks

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"time"

	"github.com/golang-jwt/jwt"
)

type FbKeyMgmt struct {
	privateKey *rsa.PrivateKey
	apiKey     string
	rnd        *rand.Rand
}

func NewInstanceKeyMgmt(pk *rsa.PrivateKey, apiKey string) *FbKeyMgmt {
	var s secrets
	k := new(FbKeyMgmt)
	k.privateKey = pk
	k.apiKey = apiKey
	k.rnd = rand.New(s)
	return k
}

func (k *FbKeyMgmt) createAndSignJWTToken(path string, bodyJSON string) (string, error) {

	token := &jwt.MapClaims{
		"uri":      path,
		"nonce":    k.rnd.Int63(),
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Second * 55).Unix(),
		"sub":      k.apiKey,
		"bodyHash": createHash(bodyJSON),
	}

	j := jwt.NewWithClaims(jwt.SigningMethodRS256, token)
	signedToken, err := j.SignedString(k.privateKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func createHash(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}
