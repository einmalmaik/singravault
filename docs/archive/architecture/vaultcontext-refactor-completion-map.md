# VaultContext Refactor Completion Map

Stand: 2026-04-29

| sectionOrFunction | currentResponsibility | targetModule | moveStrategy | testCoverage | risk |
|---|---|---|---|---|---|
| `VaultContext.tsx` | Context, Provider, Hook | `src/contexts/VaultContext.tsx` | Bleibt als Gateway/Fassade; Provider-Wert kommt aus Runtime-Hook. | `src/contexts/__tests__/VaultContext.test.tsx` | Niedrig |
| Public Context Types | Provider-API, Unlock-Options, Snapshot-Source | `src/contexts/vault/vaultContextTypes.ts` | Typen aus Gateway herausgezogen. | Typecheck, VaultContext tests | Niedrig |
| Provider State | React State fuer Lock, Setup, Integrity, Quarantaene, Recovery | `src/contexts/vault/useVaultProviderActions.tsx` jetzt, Ziel `useVaultProviderState.ts` | Noch weiter zu splitten; aktuell aus Gateway entfernt, aber Runtime-Hook bleibt gross. | VaultContext tests | Mittel |
| Lifecycle Effects | Auth-Session, Setup-Check, Online-Listener, Auto-Lock, Activity | `useVaultLifecycleEffects.ts` Ziel | Noch nicht physisch getrennt. | VaultContext tests | Mittel |
| Setup | Salt, UserKey, Default-Vault, Profile/Offline Credentials | Ziel `src/services/vaultSetupOrchestrator.ts` | Noch im Runtime-Hook; naechster Extraktionsschritt. | VaultContext setup tests | Hoch |
| Legacy-KDF-Reparatur | Legacy verifier recovery, private-key USK migration, KDF repair helpers | `src/services/legacyVaultRepairService.ts` teilweise | Private-key migration und no-verifier probe extrahiert; alter KDF-repair scan ist noch im Runtime-Hook. | VaultContext legacy tests, KDF tests | Mittel |
| Device-Key-Aktivierung | Secure storage preflight, rewrap, server state, rollback | Ziel `src/services/deviceKeyActivationService.ts` | Noch im Runtime-Hook; nicht fachlich neu geschrieben. | DeviceKey service/unlock tests, VaultContext lock tests | Hoch |
| Vault-Unlock | Master password, USK unwrap, KDF upgrade, Device-Key preconditions | `src/services/vaultUnlockOrchestrator.ts` Ziel plus Runtime-Hook | 2FA-Gate und Device-Key-required sind Services; Hauptablauf noch im Runtime-Hook. | VaultContext unlock tests, orchestrator tests | Hoch |
| Passkey-Unlock | WebAuthn challenge result, PRF errors, verifier checks | Ziel `vaultUnlockOrchestrator.ts` | Noch im Runtime-Hook. | VaultContext passkey tests | Mittel |
| 2FA-Gate | VaultFA before key release | `src/services/vaultUnlockOrchestrator.ts` | Bereits delegiert. | `vaultUnlockOrchestrator.test.ts`, VaultContext 2FA tests | Niedrig |
| Integrity Decision | Snapshot build, baseline assessment, category block, item quarantine | `src/services/vaultIntegrityDecisionEngine.ts` | Decision liegt im Service; State-Anwendung noch im Runtime-Hook. | `vaultIntegrityDecisionEngine.test.ts`, VaultContext integrity tests | Mittel |
| Quarantaene-Orchestrierung | Displayed result, decrypt guard, resolution summary | `src/services/vaultQuarantineOrchestrator.ts` und `vaultQuarantineRecoveryService.ts` | Guard/Summary delegiert; UI action state noch im Runtime-Hook. | `vaultQuarantineOrchestrator.test.ts`, VaultContext quarantine tests | Mittel |
| Trusted Snapshot Recovery | Safe mode and reset | Ziel `src/services/vaultRecoveryOrchestrator.ts` | Reset nutzt `vaultRecoveryService`; Safe Mode noch Runtime-Hook. | VaultContext tests | Mittel |
| Session Marker | sessionStorage markers only | `src/services/vaultRuntimeFacade.ts` | Bereits delegiert. | `vaultRuntimeFacade.test.ts`, VaultContext lock tests | Niedrig |
| Account-vs-Vault Route Policy | Account Settings ohne Vault Unlock | `src/services/accountVaultRoutePolicy.ts` | Bereits eigener Service. | `accountVaultRoutePolicy.test.ts` | Niedrig |
| Error Mapping | UI-safe error codes | `src/services/vaultErrorMapper.ts` | Bestehend; Context wirft teilweise noch technische Errors. | `vaultErrorMapper.test.ts` | Mittel |
