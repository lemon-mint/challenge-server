package js

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/valyala/fasthttp"
)

//Verify : verify hash
func Verify(ctx *fasthttp.RequestCtx, key []byte, banlist *fastcache.Cache) bool {
	i := ctx.QueryArgs().Peek("i")
	nonce := ctx.QueryArgs().Peek("nonce")
	parts := strings.Split(string(nonce), ".")
	if len(parts) != 3 {
		ctx.SetStatusCode(403)
		return false
	}
	if banlist.Has([]byte(parts[2])) {
		ctx.SetStatusCode(403)
		return false
	}
	exp, err := strconv.Atoi(parts[1])
	if err != nil {
		ctx.SetStatusCode(403)
		return false
	}
	if exp <= int(time.Now().UTC().Unix()) {
		ctx.SetStatusCode(403)
		return false
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte(parts[0] + "." + parts[1]))
	if base64.RawURLEncoding.EncodeToString(h.Sum(nil)) != parts[2] {
		ctx.SetStatusCode(403)
		return false
	}
	hash := sha256.Sum256([]byte(string(parts[0]) + string(i)))
	if !strings.HasPrefix(hex.EncodeToString(hash[:]), strings.Repeat("0", 5)) {
		ctx.SetStatusCode(403)
		return false
	}
	banlist.Set([]byte(parts[2]), hash[:])
	return true
}
