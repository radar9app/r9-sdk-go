// Package radar9 is the official Go SDK for the Radar9 headless help desk.
//
// Radar9 is headless: it has no login of its own and never sees your users'
// passwords. Your backend authenticates a user however it already does, then
// mints a short-lived "user token" signed with a channel's identity secret
// (r9id_...). Your app trades that token for a Radar9 session and talks to
// Radar9 directly. The only work your backend has to do is mint that token —
// and verify webhook signatures if you consume them. This SDK does both, so you
// write a few lines instead of hand-rolling a JWT.
//
// It depends on the standard library only. There is nothing else to pull in,
// and it will not clash with whichever JWT library your application already
// uses.
//
// # Install
//
//	go get github.com/radar9app/r9-sdk-go
//
// # Mint a user token
//
// Create one Client per Radar9 channel, using that channel's identity secret,
// and mint a token for the signed-in user:
//
//	hd := radar9.New(os.Getenv("RADAR9_IDENTITY_SECRET"))
//
//	token, err := hd.UserToken(radar9.Identity{
//	    UserID:      user.ID,      // your id for the user; stable per person
//	    Email:       user.Email,   // matches email tickets to the same person
//	    Name:        user.Name,
//	    CompanyID:   user.CompanyID,   // your id for the user's company (optional)
//	    CompanyName: user.CompanyName,
//	    Role:        radar9.RoleFor(user.IsCompanyAdmin),
//	})
//	// return {"user_token": token} to your app
//
// Your app then POSTs the token plus the channel's publishable key to
// /v1/client/session on Radar9 and receives a session token for the chat UI.
//
// # Or expose the endpoint in one line (net/http)
//
//	mux.Handle("/support/token", hd.TokenHandler(
//	    func(r *http.Request) (radar9.Identity, error) {
//	        u := currentUser(r) // your existing auth
//	        return radar9.Identity{
//	            UserID: u.ID, Email: u.Email, Name: u.Name,
//	            CompanyID: u.CompanyID, CompanyName: u.CompanyName,
//	            Role: radar9.RoleFor(u.IsCompanyAdmin),
//	        }, nil
//	    }))
//
// If your service is built on a custom handler framework, call UserToken
// directly inside your existing authenticated handler instead of using
// TokenHandler.
//
// # Companies and roles
//
// Radar9 groups tickets by company. What a "company" is, is entirely yours to
// decide — a tenant, an account, a team, a site — you map your own id onto
// CompanyID. A contact with Role admin sees every ticket of their company,
// including colleagues' personal ones, so assign it narrowly. Both are optional:
// omit CompanyID for a purely personal help desk.
//
// # Security
//
//   - Decide Role on the server from your session. Never read it from the
//     client, or a member could self-promote to admin and read the whole
//     company's tickets.
//   - Sign with the Radar9 identity secret, never with your application's own
//     signing key.
//   - Tokens are short-lived: default 10 minutes, hard cap 60.
package radar9

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Role is a contact's role within their company. An admin sees every ticket of
// their company, including colleagues' personal ones, so assign it narrowly.
type Role string

const (
	RoleMember Role = "member"
	RoleAdmin  Role = "admin"
)

// RoleFor maps an "is this user an admin of their company" boolean to a Role,
// for call sites that already have the flag.
func RoleFor(isAdmin bool) Role {
	if isAdmin {
		return RoleAdmin
	}
	return RoleMember
}

// defaultTTL and maxTTL bound the token lifetime. Radar9 rejects any token
// whose exp-iat exceeds maxTTL.
const (
	defaultTTL = 10 * time.Minute
	maxTTL     = 60 * time.Minute
)

// Identity describes the person a user token is minted for. UserID and Email
// are required; everything else is optional, except that an admin token needs a
// CompanyID (an admin is an admin *of* a company).
type Identity struct {
	UserID      string         // required, stable per person -> "sub"
	Email       string         // required, matches email tickets to the same person
	Name        string         // shown to agents
	CompanyID   string         // your id for the user's company (optional)
	CompanyName string         // shown to agents; updates the company name in Radar9
	Role        Role           // defaults to RoleMember
	Metadata    map[string]any // small (<=4KB) object shown to agents
	TTL         time.Duration  // optional; defaults to 10m, capped at 60m
}

// Client mints user tokens for one Radar9 channel.
type Client struct {
	secret string
	now    func() time.Time
}

// Option configures a Client.
type Option func(*Client)

// WithClock overrides the time source. Useful in tests.
func WithClock(now func() time.Time) Option {
	return func(c *Client) { c.now = now }
}

// New returns a Client that signs tokens with the given channel identity
// secret (r9id_...). It panics if the secret is empty, since a Client without
// one can never produce a valid token and that is always a wiring mistake.
func New(identitySecret string, opts ...Option) *Client {
	if identitySecret == "" {
		panic("radar9: identity secret is empty")
	}
	c := &Client{secret: identitySecret, now: time.Now}
	for _, o := range opts {
		o(c)
	}
	return c
}

// ErrInvalidIdentity is returned by UserToken when the Identity is not usable.
var ErrInvalidIdentity = errors.New("radar9: invalid identity")

// UserToken signs a short-lived HS256 user token for the given identity.
func (c *Client) UserToken(id Identity) (string, error) {
	if id.UserID == "" || id.Email == "" {
		return "", fmt.Errorf("%w: UserID and Email are required", ErrInvalidIdentity)
	}
	role := id.Role
	if role == "" {
		role = RoleMember
	}
	if role != RoleMember && role != RoleAdmin {
		return "", fmt.Errorf("%w: Role must be member or admin", ErrInvalidIdentity)
	}
	if role == RoleAdmin && id.CompanyID == "" {
		return "", fmt.Errorf("%w: an admin token needs a CompanyID", ErrInvalidIdentity)
	}
	ttl := id.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	if ttl > maxTTL {
		return "", fmt.Errorf("%w: TTL %s exceeds the 60m cap", ErrInvalidIdentity, ttl)
	}
	if id.Metadata != nil {
		if b, err := json.Marshal(id.Metadata); err != nil {
			return "", fmt.Errorf("%w: metadata is not JSON-serialisable: %v", ErrInvalidIdentity, err)
		} else if len(b) > 4096 {
			return "", fmt.Errorf("%w: metadata exceeds 4KB", ErrInvalidIdentity)
		}
	}

	now := c.now()
	claims := map[string]any{
		"sub":   id.UserID,
		"email": id.Email,
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
	}
	if id.Name != "" {
		claims["name"] = id.Name
	}
	if id.CompanyID != "" {
		claims["company_id"] = id.CompanyID
		claims["company_role"] = string(role)
	}
	if id.CompanyName != "" {
		claims["company_name"] = id.CompanyName
	}
	if len(id.Metadata) > 0 {
		claims["metadata"] = id.Metadata
	}

	return c.sign(claims)
}

// TokenResponse is the JSON body TokenHandler returns on success.
type TokenResponse struct {
	UserToken string `json:"user_token"`
}

// TokenHandler returns an http.Handler that resolves the caller's identity with
// resolve, mints a user token, and writes {"user_token": "..."} as JSON. If
// resolve returns an error the request is treated as unauthenticated (401).
//
// resolve must derive the identity — and especially the Role — from the
// server-side session, never from the request body.
func (c *Client) TokenHandler(resolve func(*http.Request) (Identity, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := resolve(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tok, err := c.UserToken(id)
		if err != nil {
			http.Error(w, "could not issue support token", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{UserToken: tok})
	}
}

// sign builds a compact HS256 JWT (header.claims.signature).
func (c *Client) sign(claims map[string]any) (string, error) {
	header := b64(`{"alg":"HS256","typ":"JWT"}`)
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("radar9: encode claims: %w", err)
	}
	signingInput := header + "." + b64(string(payload))
	mac := hmac.New(sha256.New, []byte(c.secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig, nil
}

func b64(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// ErrBadSignature is returned by VerifyWebhook when a webhook can't be trusted.
var ErrBadSignature = errors.New("radar9: webhook signature verification failed")

// VerifyWebhook checks a Radar9 webhook signature. Pass the raw request body,
// the X-Radar9-Signature header value (formatted "t=<unix>,v1=<hex hmac>"), the
// channel's webhook secret (r9wh_...), and how much clock skew to tolerate
// (e.g. 5*time.Minute; pass 0 to skip the freshness check). It returns nil when
// the signature is valid and fresh.
//
// Read the body once as raw bytes and verify before parsing it — re-encoding
// JSON would change the bytes the signature was computed over.
func VerifyWebhook(webhookSecret string, body []byte, signatureHeader string, tolerance time.Duration) error {
	var tsPart, sigPart string
	for _, field := range strings.Split(signatureHeader, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			tsPart = v
		case "v1":
			sigPart = v
		}
	}
	if tsPart == "" || sigPart == "" {
		return fmt.Errorf("%w: header missing t or v1", ErrBadSignature)
	}
	ts, err := strconv.ParseInt(tsPart, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: bad timestamp", ErrBadSignature)
	}
	if tolerance > 0 {
		age := time.Since(time.Unix(ts, 0))
		if age < 0 {
			age = -age
		}
		if age > tolerance {
			return fmt.Errorf("%w: timestamp outside tolerance", ErrBadSignature)
		}
	}
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	fmt.Fprintf(mac, "%d.%s", ts, body)
	want := mac.Sum(nil)
	got, err := hexDecode(sigPart)
	if err != nil {
		return fmt.Errorf("%w: signature is not hex", ErrBadSignature)
	}
	if !hmac.Equal(want, got) {
		return ErrBadSignature
	}
	return nil
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd length")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, err := hexVal(s[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexVal(s[2*i+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(b byte) (byte, error) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', nil
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, nil
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, nil
	}
	return 0, errors.New("bad hex digit")
}
