// Package oidctest mints unsigned JWT-shaped tokens for tests. The CLI
// reads a token's audience before it sends it (it never verifies the
// signature; SigComply Cloud does), so a test token needs a real payload.
package oidctest

import (
	"encoding/base64"
	"encoding/json"
)

// JWT returns header.payload.signature with the given audiences in
// `aud`: a string for one, an array for several, absent for none. The
// signature segment is a placeholder.
func JWT(aud ...string) string {
	claims := map[string]any{"iss": "https://issuer.test", "sub": "test"}
	switch len(aud) {
	case 0:
	case 1:
		claims["aud"] = aud[0]
	default:
		claims["aud"] = aud
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err) // a map of strings always marshals
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc.EncodeToString(payload) + ".sig"
}
