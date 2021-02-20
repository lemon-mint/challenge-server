package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"time"

	"github.com/lemon-mint/challenge-server/encryption"
	"github.com/valyala/fasthttp"
	"github.com/zeebo/blake3"
)

var server = []byte("challengeserver")
var useXFF bool = true

func main() {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	p := encryption.NewPacker(key)
	fasthttp.ListenAndServe(":59710", func(ctx *fasthttp.RequestCtx) {
		//ctx.Response.Header.SetServerBytes(server)
		switch string(ctx.Path()) {
		case "/":
			ctx.SetBody(indexHTML)
			ctx.SetContentType("text/html")
		case "/verify/cookie":
			verifyWithCookie(ctx, p)
		case "/token/new":
			i := ctx.QueryArgs().Peek("i")
			nonce := ctx.QueryArgs().Peek("nonce")
			hash := sha256.Sum256([]byte(string(nonce) + string(i)))
			if !strings.HasPrefix(hex.EncodeToString(hash[:]), strings.Repeat("0", 5)) {
				ctx.SetStatusCode(403)
				return
			}
			token, err := p.NewToken(time.Minute*30, getID(ctx))
			if err != nil {
				ctx.SetStatusCode(403)
				return
			}
			tracker := fasthttp.AcquireCookie()
			tracker.SetKey("_go_clearance")
			tracker.SetHTTPOnly(true)
			tracker.SetValue(token)
			tracker.SetPath("/")
			ctx.Response.Header.SetCookie(tracker)
			fasthttp.ReleaseCookie(tracker)
		case "/random":
			buf := make([]byte, 32)
			io.ReadFull(rand.Reader, buf)
			uuid := base64.RawURLEncoding.EncodeToString(buf)
			ctx.WriteString(uuid)
		case "/challenge":
			ctx.SendFile("challenges/js/index.html")
		default:
			ctx.SetStatusCode(404)
			ctx.SetBodyString("Error 404 Not Found")
		}
	})
}

func verifyWithCookie(ctx *fasthttp.RequestCtx, p *encryption.Packer) {
	token := ctx.Request.Header.Cookie("_go_clearance")
	/*if token == nil {
		ctx.SetStatusCode(403)
		return
	}*/
	//fmt.Println(getID(ctx))
	if !p.Verify(string(token), getID(ctx)) {
		ctx.SetStatusCode(403)
		return
	}
	ctx.SetStatusCode(200)
	ctx.SetContentType("text/plain")
	ctx.WriteString("OK 200")
}

func getID(ctx *fasthttp.RequestCtx) string {
	h := blake3.New()
	h.Write(ctx.UserAgent())
	h.Write(ctx.Host())
	h.WriteString(ctx.RemoteIP().String())
	userTrack := ctx.Request.Header.Cookie("_clearance_track")
	if userTrack == nil {
		buf := make([]byte, 8)
		io.ReadFull(rand.Reader, buf)
		uuid := base64.RawURLEncoding.EncodeToString(buf)
		h.WriteString(uuid)
		tracker := fasthttp.AcquireCookie()
		tracker.SetKey("_clearance_track")
		tracker.SetHTTPOnly(true)
		tracker.SetValue(uuid)
		tracker.SetPath("/")
		ctx.Response.Header.SetCookie(tracker)
		fasthttp.ReleaseCookie(tracker)
	} else {
		h.Write(userTrack)
	}
	if useXFF {
		xff := ctx.Request.Header.Peek("X-Forwarded-For")
		h.Write(xff)
	}
	hash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	//fmt.Println(hash)
	return hash
}

func randstr(size int) string {
	buf := make([]byte, size)
	io.ReadFull(rand.Reader, buf)
	uuid := base64.RawURLEncoding.EncodeToString(buf)
	return uuid
}
