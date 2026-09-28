# radar9-go

The official Go SDK for the [Radar9](https://radar9.tech) headless help desk.

Radar9 is headless: it has no login of its own and never sees your users'
passwords. Your backend authenticates a user however it already does, then mints
a short-lived **user token** signed with a channel's identity secret. Your app
trades that token for a Radar9 session and talks to Radar9 directly. The only
backend work is minting that token (and verifying webhook signatures, if you
consume them). This SDK does both, so you write a few lines instead of
hand-rolling a JWT.

Standard library only — nothing else to pull in, and no clash with whichever JWT
library your application already uses.

## Install

```sh
go get github.com/radar9app/r9-sdk-go
```

```go
import radar9 "github.com/radar9app/r9-sdk-go"
```

## Mint a user token

Create one `Client` per Radar9 channel, using that channel's identity secret:

```go
hd := radar9.New(os.Getenv("RADAR9_IDENTITY_SECRET"))

token, err := hd.UserToken(radar9.Identity{
    UserID:      user.ID,        // your id for the user; stable per person
    Email:       user.Email,     // matches email tickets to the same person
    Name:        user.Name,
    CompanyID:   user.CompanyID,  // your id for the user's company (optional)
    CompanyName: user.CompanyName,
    Role:        radar9.RoleFor(user.IsCompanyAdmin), // decided on the server
})
// return {"user_token": token} to your app
```

Your app then POSTs the token plus the channel's publishable key to
`/v1/client/session` and gets a session token for the chat UI.

## Or expose the endpoint (net/http)

```go
mux.Handle("/support/token", hd.TokenHandler(
    func(r *http.Request) (radar9.Identity, error) {
        u := currentUser(r) // your existing auth
        return radar9.Identity{
            UserID: u.ID, Email: u.Email, Name: u.Name,
            CompanyID: u.CompanyID, CompanyName: u.CompanyName,
            Role: radar9.RoleFor(u.IsCompanyAdmin),
        }, nil
    }))
```

On a custom handler framework, call `UserToken` inside your existing
authenticated handler instead of using `TokenHandler`.

## Companies and roles

Radar9 groups tickets by company. What a "company" is, is yours to decide — a
tenant, an account, a team, a site — you map your own id onto `CompanyID`. A
contact with `Role` admin sees every ticket of their company, including
colleagues' personal ones, so assign it narrowly. Both fields are optional; omit
`CompanyID` for a purely personal help desk.

## Verify webhooks

```go
if err := radar9.VerifyWebhook(secret, rawBody, r.Header.Get("X-Radar9-Signature"), 5*time.Minute); err != nil {
    http.Error(w, "bad signature", http.StatusUnauthorized)
    return
}
```

Read the body as raw bytes and verify **before** parsing — re-encoding JSON
changes the bytes the signature was computed over.

## Rules

- Decide `Role` on the server from your session. Never read it from the client.
- Sign with the Radar9 identity secret, never your application's own key.
- Tokens are short-lived: default 10 minutes, hard cap 60.

## Reference

Full API — endpoints, WebSocket frames, error codes, a reference JS client — is
in the Radar9 help desk integration guide.

## License

MIT — see [LICENSE](LICENSE).
