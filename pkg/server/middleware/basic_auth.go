package middleware

import (
	"os"
	"strings"

	"github.com/cespare/xxhash"
	"github.com/siglens/siglens/pkg/utils"
	"github.com/valyala/fasthttp"
)

func BasicAuthMiddleware(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {

		user := strings.TrimSpace(os.Getenv("SIGLENS_USER"))
		pass := strings.TrimSpace(os.Getenv("SIGLENS_PASS"))
		if user == "" || len(pass) < 32 {
			ctx.Response.Header.Add("WWW-Authenticate", `Basic realm="basic_auth_misconfigured"`)
			ctx.Response.SetStatusCode(fasthttp.StatusUnauthorized)
			return
		}

		usernameHash := xxhash.Sum64String(user)
		passwordHash := xxhash.Sum64String(pass)

		if !utils.VerifyBasicAuth(ctx, usernameHash, passwordHash) {
			ctx.Response.Header.Add("WWW-Authenticate", `Basic realm="username and password required"`)
			ctx.Response.SetStatusCode(fasthttp.StatusUnauthorized)
			return
		}

		next(ctx)
	}
}
