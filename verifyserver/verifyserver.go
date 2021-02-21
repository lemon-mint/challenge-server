package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/lemon-mint/challenge-server/challenges/js"
	"github.com/lemon-mint/challenge-server/encryption"
	"github.com/lemon-mint/godotenv"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"github.com/valyala/fasthttp"
	"github.com/zeebo/blake3"
)

var server = []byte("challengeserver")
var useXFF bool = true
var useRateLimit = false

var lim *limiter.Limiter

func main() {
	godotenv.Load()
	key := make([]byte, 32)

	if os.Getenv("USE_RATE_LIMIT") != "" {
		useRateLimit = true
		rate, err := limiter.NewRateFromFormatted(os.Getenv("USE_RATE_LIMIT"))
		if err != nil {
			panic(err)
		}
		lim = limiter.New(memory.NewStore(), rate)
	}

	if os.Getenv("SECRET_KEY") == "" {
		io.ReadFull(rand.Reader, key)
	} else {
		h := blake3.New()
		h.WriteString(os.Getenv("SECRET_KEY"))
		h.WriteString(os.Getenv("SECRET_KEY"))
		h.WriteString(os.Getenv("SECRET_KEY"))
		h.WriteString(os.Getenv("SECRET_KEY"))
		h.WriteString(os.Getenv("SECRET_KEY"))
		copy(key, h.Sum(nil))
	}
	p := encryption.NewPacker(key)

	banlist := fastcache.New(32)

	fasthttp.ListenAndServe(":59710", func(ctx *fasthttp.RequestCtx) {
		//ctx.Response.Header.SetServerBytes(server)
		switch string(ctx.Path()) {
		case "/":
			ctx.SetBody(indexHTML)
			ctx.SetContentType("text/html")
		case "/verify/cookie":
			verifyWithCookie(ctx, p, banlist)
		case "/_v_challenge/token/new":
			if !js.Verify(ctx, key, banlist) {
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
			fmt.Println("New Token:", token)
		case "/random":
			buf := make([]byte, 32)
			io.ReadFull(rand.Reader, buf)
			uuid := base64.RawURLEncoding.EncodeToString(buf)
			ctx.WriteString(uuid)
		case "/challenge":
			ctx.SendFile("challenges/js/index.html")
		case "/_v_challenge/token/nonce":
			nonce := randstr(16)
			exp := fmt.Sprint(time.Now().UTC().Add(time.Second * 120).Unix())
			h := hmac.New(sha256.New, key)
			h.Write([]byte(nonce + "." + exp))
			ctx.WriteString(nonce + "." + exp + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil)))
		case "/revoke":
			token := ctx.Request.Header.Cookie("_go_clearance")
			if token != nil {
				var info []byte
				info = append(info, []byte(time.Now().String())...)
				info = append(info, ctx.UserAgent()...)
				info = append(info, ctx.RemoteIP()...)
				info = append(info, ctx.Request.Header.Peek("X-Forwarded-For")...)

				banlist.Set(token, info)
				ctx.WriteString("revoked")
			}
		default:
			ctx.SetStatusCode(404)
			ctx.SetBodyString("Error 404 Not Found")
		}
	})
}

func verifyWithCookie(ctx *fasthttp.RequestCtx, p *encryption.Packer, banlist *fastcache.Cache) {

	token := ctx.Request.Header.Cookie("_go_clearance")
	if token == nil {
		ctx.SetStatusCode(403)
		return
	}

	if banlist.Has(token) {
		ctx.SetStatusCode(403)
		return
	}
	strtoken := string(token)
	if useRateLimit {
		limctx, err := lim.Get(ctx, strtoken)
		if err != nil {
			ctx.SetStatusCode(403)
			return
		}
		if limctx.Reached {
			ctx.SetStatusCode(403)
			return
		}
	}

	//fmt.Println(getID(ctx))
	if !p.Verify(strtoken, getID(ctx)) {
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
