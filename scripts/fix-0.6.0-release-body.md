// Run this once to set the 0.6.0 release body on GitHub.
// Requires: `gh auth login` (or GH_TOKEN env).
// Usage:    gh release edit v0.6.0 --notes-file RELEASE-NOTES-0.6.0.md
// Alternative (no gh): curl -X PATCH the release with a token — see github-release-body-payload.json

{
  "tag_name": "v0.6.0",
  "name": "Singra Vault v0.6.0 — DIS Crypto Cutover",
  "body_path": "RELEASE-NOTES-0.6.0.md"
}
