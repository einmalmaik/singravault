# ThemeProvider — Theme-Verwaltung

> **Datei:** `src/contexts/ThemeProvider.tsx`  
> **Zweck:** Verwaltung des UI-Themes (Light, Dark, System) mit Persistenz in `localStorage`.

---

## Context-Interface

```typescript
interface ThemeContextType {
    theme: 'light' | 'dark' | 'system';       // Gewähltes Theme
    setTheme: (theme) => void;                  // Theme setzen
    resolvedTheme: 'light' | 'dark';           // Tatsächlich angewendetes Theme
}
```

---

## `ThemeProvider` — React Context Provider

### Props

| Prop | Typ | Default | Beschreibung |
|---|---|---|---|
| `children` | `ReactNode` | — | Kindkomponenten |
| `defaultTheme` | `Theme` | `'system'` | Fallback-Theme |
| `storageKey` | `string` | `'singra-ui-theme'` | localStorage-Key |

---

### Initialisierung

**Ablauf:**
1. Liest gespeichertes Theme aus `localStorage`
2. Fallback auf `defaultTheme`

---

### Theme-Anwendung (useEffect)

Wird bei jeder Theme-Änderung ausgeführt.

**Ablauf:**
1. Entfernt `light` und `dark` Klasse vom `<html>`-Element
2. **Theme = `'system'`:**
   - Prüft `window.matchMedia('(prefers-color-scheme: dark)')`
   - Wendet das System-Theme an
   - Setzt `resolvedTheme` auf das erkannte System-Theme
3. **Sonst:** Wendet `light` oder `dark` direkt an

---

### System-Theme-Listener (useEffect)

Registriert einen `MediaQueryListEvent`-Listener auf `(prefers-color-scheme: dark)`.

**Ablauf:**
1. Nur aktiv wenn Theme = `'system'`
2. Bei Änderung der System-Einstellung → aktualisiert das angewendete Theme
3. **Cleanup:** Entfernt Listener bei Unmount

---

### `setTheme(theme): void`

Setzt das Theme und persistiert es.

**Ablauf:**
1. Speichert in `localStorage` unter `storageKey`
2. Aktualisiert den State

---

## Hook: `useTheme()`

```typescript
export function useTheme(): ThemeContextType
```

Zugriff auf den Theme-Kontext. Wirft `Error` wenn außerhalb des `ThemeProvider` verwendet.
