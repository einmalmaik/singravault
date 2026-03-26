# Vault Item Dialog Create-Type Restrictions (March 2026)

## Summary

The shared `VaultItemDialog` now accepts an `allowedTypes` prop so callers can
restrict which item kinds may be created without forking the dialog.

## Behavior

- `/vault` opens the dialog with `['password', 'note']`
- `/authenticator` opens the dialog with `['totp']`
- Existing item edits ignore the create restriction and still load the saved item type
- `initialType` is re-evaluated every time the dialog opens, which fixes the
  old reset bug where authenticator-only flows fell back to `password`

## Deep-Link Support

`/vault` now reads `?edit=<itemId>` and opens the matching item directly in the
editor. The query params are removed immediately after the dialog opens so the
URL does not stay sticky.
