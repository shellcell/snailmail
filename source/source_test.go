package source

import (
	"net/url"
	"testing"
)

// A release asset redirects to object storage, which puts its signature in the
// query. Refusing that made every GitHub Release asset unfetchable, so a
// redirect target is allowed one while everything else stays refused.
func TestValidateRedirectURLAllowsASignedQuery(t *testing.T) {
	signed := "https://release-assets.githubusercontent.com/github-production-release-asset/1307517728/" +
		"29e5d995?sp=r&sv=2018-11-09&sr=b&sig=4bmcg0tdz%2B%2B8gI%2BJqslOcMfM2I9mILAK6H7kiJbGjLM%3D"
	parsed, err := url.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRedirectURL(parsed); err != nil {
		t.Fatalf("a signed redirect was refused: %v", err)
	}
	// The operator-supplied rule is unchanged: that URL is committed as an
	// origin, and a query is where a credential would hide.
	if err := ValidatePublicURL(parsed); err == nil {
		t.Fatal("a query was accepted on an operator-supplied URL")
	}
}

func TestValidateRedirectURLStillRefusesUnsafeTargets(t *testing.T) {
	for name, raw := range map[string]string{
		"plain http":  "http://example.com/asset?sig=x",
		"credentials": "https://user:pass@example.com/asset?sig=x",
		"loopback":    "https://127.0.0.1/asset?sig=x",
		"private":     "https://10.0.0.1/asset?sig=x",
		"dot segment": "https://example.com/a/../b?sig=x",
		"fragment":    "https://example.com/asset?sig=x#f",
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateRedirectURL(parsed); err == nil {
				t.Fatalf("%s was accepted as a redirect target", raw)
			}
		})
	}
}
