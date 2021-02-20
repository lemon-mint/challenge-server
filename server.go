package main

import "github.com/valyala/fasthttp"

func main() {
	fasthttp.ListenAndServe(":59710", func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/":
		}
	})
}
