package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const SigningSchema = 1

type SigningRequirement struct {
	Format            string   `json:"format"`
	RepositorySigning bool     `json:"repository_signing"`
	Algorithms        []string `json:"algorithms"`
	PublicForms       []string `json:"public_forms"`
}

var signingRequirements = []SigningRequirement{
	{Format: "apk", RepositorySigning: true, Algorithms: []string{"apk-rsa4096"}, PublicForms: []string{"named-rsa-public-key"}},
	{Format: "cargo", RepositorySigning: false},
	{Format: "deb", RepositorySigning: true, Algorithms: []string{"openpgp-ed25519", "openpgp-rsa4096"}, PublicForms: []string{"openpgp-binary", "openpgp-armored"}},
	{Format: "go", RepositorySigning: false},
	{Format: "helm", RepositorySigning: true, Algorithms: []string{"openpgp-ed25519", "openpgp-rsa4096"}, PublicForms: []string{"openpgp-armored"}},
	{Format: "maven", RepositorySigning: true, Algorithms: []string{"openpgp-ed25519", "openpgp-rsa4096"}, PublicForms: []string{"openpgp-armored"}},
	{Format: "nix", RepositorySigning: true, Algorithms: []string{"nix-ed25519"}, PublicForms: []string{"nix-public-key"}},
	{Format: "npm", RepositorySigning: false},
	{Format: "pypi", RepositorySigning: false},
	{Format: "rpm", RepositorySigning: true, Algorithms: []string{"openpgp-rsa4096"}, PublicForms: []string{"openpgp-armored"}},
}

func SigningRequirements() []SigningRequirement {
	result := make([]SigningRequirement, len(signingRequirements))
	for index, requirement := range signingRequirements {
		result[index] = requirement
		result[index].Algorithms = append([]string(nil), requirement.Algorithms...)
		result[index].PublicForms = append([]string(nil), requirement.PublicForms...)
	}
	return result
}

func SigningDigest() string {
	content, err := json.Marshal(struct {
		Schema       int                  `json:"schema"`
		Requirements []SigningRequirement `json:"requirements"`
	}{Schema: SigningSchema, Requirements: signingRequirements})
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func Compatible(format, algorithm string) bool {
	for _, requirement := range signingRequirements {
		if requirement.Format != format {
			continue
		}
		for _, allowed := range requirement.Algorithms {
			if allowed == algorithm {
				return true
			}
		}
	}
	return false
}
