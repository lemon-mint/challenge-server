package encryption

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"time"

	"github.com/lemon-mint/challenge-server/token"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
)

//Packer : sign encrypt verify decrypt
type Packer struct {
	aead cipher.AEAD
}

//NewPacker : Create New Packer
func NewPacker(key []byte) {
	h := blake3.New()
	h.Write(key)
	p := new(Packer)
	p.aead = chacha20poly1305.NewX(h.Sum(nil))
}

//NewToken : Create New token
func (p *Packer) NewToken(exp time.Duration, id string) ([]byte, error) {
	buf := make([]byte, 8)
	io.ReadFull(rand.Reader, buf)
	t := &token.AccessToken{
		Timestamp: time.Now().UTC().Unix(),
		Expire:    time.Now().UTC().Add(exp).Unix(),
		Id:        id,
		Nonce:     buf,
	}
	nonce := make([]byte, p.aead.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	msg, err := proto.Marshal(t)
	if err != nil {
		return nil, err
	}
	encrypted := p.aead.Seal(nil, nonce, msg, nil)
	buf = make([]byte, len(encrypted)+p.aead.NonceSize())
	copy(buf[:p.aead.NonceSize()], nonce)
	copy(buf[p.aead.NonceSize():], encrypted)
	return buf, nil
}

//Verify : token
func (p *Packer) Verify(tokenString string, id string) bool {
	encrypted, err := base64.RawStdEncoding.DecodeString(tokenString)
	if err != nil {
		return false
	}
	if len(encrypted) <= p.aead.NonceSize() {
		return false
	}
	msg, err := p.aead.Open(nil, encrypted[:p.aead.NonceSize()], encrypted[p.aead.NonceSize():], nil)
	if err != nil {
		return false
	}
	t := new(token.AccessToken)
	err = proto.Unmarshal(msg, t)
	if err != nil {
		return false
	}
	if t.Expire >= time.Now().Unix() {
		return false
	}
	if t.Id != id {
		return false
	}
	return true
}
