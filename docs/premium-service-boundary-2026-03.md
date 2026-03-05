# Premium Service Boundary (March 2026)

## Summary

Core (`singravault`) now keeps only the extension contracts for premium features.
The concrete implementations for family, emergency access, shared collections,
file attachments, support, vault health, and vault integrity live in `singra-premium`.

## Moved Out Of Core

- `src/services/familyService.ts`
- `src/services/emergencyAccessService.ts`
- `src/services/collectionService.ts`
- `src/services/fileAttachmentService.ts`
- `src/services/supportService.ts`
- `src/services/vaultHealthService.ts`
- `src/services/vaultIntegrityService.ts`
- Related core-only duplicate tests/components for these services

## Core Integration Pattern

`VaultContext` no longer imports `vaultIntegrityService` directly.
It now uses optional hooks from `getServiceHooks()`:

- `deriveIntegrityKey`
- `verifyVaultIntegrity`
- `updateIntegrityRoot`
- `clearIntegrityRoot`

When premium is not loaded, these hooks are absent and integrity checks are skipped gracefully.

## Premium Registration

`singra-premium/src/extensions/initPremium.ts` registers the integrity hooks via `registerServiceHooks(...)`.

## Notes

This change keeps the open-core boundary explicit:

- Core owns slot/hook contracts and fallback behavior.
- Premium owns premium feature implementations.
