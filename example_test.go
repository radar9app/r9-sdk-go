package radar9_test

import (
	"fmt"
	"net/http"

	radar9 "github.com/radar9app/r9-sdk-go"
)

// Mint a token inside an existing authenticated handler.
func ExampleClient_UserToken() {
	hd := radar9.New("r9id_your_channel_secret")

	token, err := hd.UserToken(radar9.Identity{
		UserID:      "user_123",
		Email:       "jane@example.com",
		Name:        "Jane Doe",
		CompanyID:   "acme",
		CompanyName: "Acme Inc.",
		Role:        radar9.RoleFor(false), // decide on the server, never from the client
		Metadata:    map[string]any{"plan": "pro"},
	})
	if err != nil {
		// handle: reply 400/500
		return
	}
	_ = token // return {"user_token": token} to your app
	fmt.Println("ok")
	// Output: ok
}

// Mount the endpoint directly on a net/http mux in one line.
func ExampleClient_TokenHandler() {
	hd := radar9.New("r9id_your_channel_secret")

	mux := http.NewServeMux()
	mux.Handle("/support/token", hd.TokenHandler(
		func(r *http.Request) (radar9.Identity, error) {
			// Derive everything, especially Role, from the server session.
			return radar9.Identity{
				UserID:      "user_123",
				Email:       "jane@example.com",
				CompanyID:   "acme",
				CompanyName: "Acme Inc.",
				Role:        radar9.RoleAdmin,
			}, nil
		}))
	_ = mux
}

// Verify a webhook before trusting its body.
func ExampleVerifyWebhook() {
	handler := func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		sig := r.Header.Get("X-Radar9-Signature")

		if err := radar9.VerifyWebhook("r9wh_secret", body, sig, 0); err != nil {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		// safe to parse body and act on it
	}
	_ = handler
}
