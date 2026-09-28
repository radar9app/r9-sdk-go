package radar9

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testSecret = "r9id_test_secret"

// decodeClaims verifies the signature the way Radar9 would, then returns the
// claims. It fails the test if the token is malformed or the signature is wrong.
func decodeClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if parts[2] != want {
		t.Fatalf("signature mismatch")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

func TestUserTokenClaims(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0)
	c := New(testSecret, WithClock(func() time.Time { return fixed }))

	tok, err := c.UserToken(Identity{
		UserID:      "u1",
		Email:       "jane@acme.com",
		Name:        "Jane",
		CompanyID:   "wh_42",
		CompanyName: "Acme YUL-2",
		Role:        RoleAdmin,
		Metadata:    map[string]any{"platform": "wms_central"},
	})
	if err != nil {
		t.Fatalf("UserToken: %v", err)
	}
	claims := decodeClaims(t, tok)

	if claims["sub"] != "u1" || claims["email"] != "jane@acme.com" {
		t.Errorf("sub/email wrong: %v", claims)
	}
	if claims["company_id"] != "wh_42" || claims["company_role"] != "admin" {
		t.Errorf("company claims wrong: %v", claims)
	}
	if claims["iat"].(float64) != float64(fixed.Unix()) {
		t.Errorf("iat wrong: %v", claims["iat"])
	}
	if claims["exp"].(float64) != float64(fixed.Add(defaultTTL).Unix()) {
		t.Errorf("exp should default to 10m: %v", claims["exp"])
	}
	if exp, iat := claims["exp"].(float64), claims["iat"].(float64); exp-iat > 3600 {
		t.Errorf("exp-iat must be <= 3600, got %v", exp-iat)
	}
}

func TestUserTokenDefaultsRoleMemberAndOmitsCompany(t *testing.T) {
	c := New(testSecret)
	tok, err := c.UserToken(Identity{UserID: "u1", Email: "x@y.com"})
	if err != nil {
		t.Fatalf("UserToken: %v", err)
	}
	claims := decodeClaims(t, tok)
	if _, ok := claims["company_id"]; ok {
		t.Errorf("company_id should be omitted when empty")
	}
	if _, ok := claims["company_role"]; ok {
		t.Errorf("company_role should be omitted without a company")
	}
}

func TestUserTokenValidation(t *testing.T) {
	c := New(testSecret)
	cases := map[string]Identity{
		"missing email": {UserID: "u1"},
		"missing user":  {Email: "x@y.com"},
		"admin no company": {
			UserID: "u1", Email: "x@y.com", Role: RoleAdmin,
		},
		"ttl too long": {
			UserID: "u1", Email: "x@y.com", TTL: 2 * time.Hour,
		},
	}
	for name, id := range cases {
		if _, err := c.UserToken(id); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestTokenHandler(t *testing.T) {
	c := New(testSecret)
	h := c.TokenHandler(func(r *http.Request) (Identity, error) {
		return Identity{UserID: "u1", Email: "x@y.com"}, nil
	})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/support/token", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body TokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.UserToken == "" {
		t.Errorf("empty user_token")
	}
	decodeClaims(t, body.UserToken)
}

func TestTokenHandlerUnauthorized(t *testing.T) {
	c := New(testSecret)
	h := c.TokenHandler(func(r *http.Request) (Identity, error) {
		return Identity{}, fmt.Errorf("no session")
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func signWebhook(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.%s", ts, body)
	return fmt.Sprintf("t=%d,v1=%x", ts, mac.Sum(nil))
}

func TestVerifyWebhook(t *testing.T) {
	secret := "r9wh_secret"
	body := []byte(`{"event":"ticket.created"}`)
	now := time.Now().Unix()

	if err := VerifyWebhook(secret, body, signWebhook(secret, now, body), 5*time.Minute); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := VerifyWebhook(secret, body, signWebhook("wrong", now, body), 5*time.Minute); err == nil {
		t.Errorf("wrong secret accepted")
	}
	if err := VerifyWebhook(secret, append(body, '!'), signWebhook(secret, now, body), 5*time.Minute); err == nil {
		t.Errorf("tampered body accepted")
	}
	stale := time.Now().Add(-10 * time.Minute).Unix()
	if err := VerifyWebhook(secret, body, signWebhook(secret, stale, body), 5*time.Minute); err == nil {
		t.Errorf("stale timestamp accepted")
	}
	if err := VerifyWebhook(secret, body, "garbage", 5*time.Minute); err == nil {
		t.Errorf("garbage header accepted")
	}
}
