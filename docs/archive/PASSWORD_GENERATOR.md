# PasswordGenerator — Passwort- & Passphrasen-Generierung

> **Datei:** `src/services/passwordGenerator.ts`  
> **Zweck:** Kryptographisch sichere Generierung von Passwörtern und Passphrasen über die Web Crypto API (`crypto.getRandomValues()`).

---

## Zeichensätze

| Key | Inhalt |
|---|---|
| `uppercase` | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
| `lowercase` | `abcdefghijklmnopqrstuvwxyz` |
| `numbers` | `0123456789` |
| `symbols` | `!@#$%^&*()_+-=[]{}|;:,.<>?` |

**Wortliste (Passphrasen):** 88 englische Wörter, kuratiert für Einprägsamkeit (z.B. `apple`, `dragon`, `lighthouse`, `quantum`, `phoenix`).

---

## Funktionen

### `generatePassword(options): string`

Generiert ein kryptographisch sicheres Zufallspasswort.

**Parameter:**
```typescript
interface PasswordOptions {
    length: number;       // Gewünschte Passwortlänge
    uppercase: boolean;   // Großbuchstaben einbeziehen
    lowercase: boolean;   // Kleinbuchstaben einbeziehen
    numbers: boolean;     // Ziffern einbeziehen
    symbols: boolean;     // Sonderzeichen einbeziehen
}
```

**Ablauf:**
1. Baut den Zeichen-Pool basierend auf den Optionen zusammen
2. **Für jede aktivierte Kategorie:** Zieht sofort **ein** zufälliges Zeichen daraus → `requiredChars[]` (garantiert, dass jede Kategorie vertreten ist)
3. Füllt die restliche Länge (`length - requiredChars.length`) mit zufälligen Zeichen aus dem gesamten Pool
4. **Fisher-Yates-Shuffle** (kryptographisch sicher) über das gesamte Array
5. Vereinigt zum fertigen Passwort

**Fallback:** Wenn keine Kategorie ausgewählt → nur Kleinbuchstaben.

**Rückgabe:** Generierter Passwort-String

---

### `generatePassphrase(options): string`

Generiert eine Passphrase aus zufälligen Wörtern.

**Parameter:**
```typescript
interface PassphraseOptions {
    wordCount: number;      // Anzahl Wörter
    separator: string;      // Trennzeichen (z.B. '-')
    capitalize: boolean;    // Erster Buchstabe groß
    includeNumber: boolean; // Zufällige 3-stellige Zahl anhängen
}
```

**Ablauf:**
1. Zieht `wordCount` zufällige Wörter aus `WORD_LIST` via `getSecureRandomElement()`
2. Optional: Erster Buchstabe jedes Worts wird großgeschrieben
3. Verbindet Wörter mit `separator`
4. Optional: Hängt eine zufällige Zahl zwischen 100–999 an (via `getSecureRandomInt()`)

**Beispielausgabe:** `Phoenix-Glacier-Ember-284`

---

### `calculateStrength(password): PasswordStrength`

Berechnet die Stärke eines Passworts anhand der Shannon-Entropie.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `password` | `string` | Zu analysierendes Passwort |

**Ablauf:**
1. **Charset-Erkennung** per RegEx:
   - `/[a-z]/` → +26
   - `/[A-Z]/` → +26
   - `/[0-9]/` → +10
   - `/[^a-zA-Z0-9]/` → +32
2. **Entropie-Berechnung:** `entropy = length × log₂(charsetSize)`
3. **Bewertung nach Entropie-Schwellwerten:**

| Entropie | Score | Label | Farbe |
|---|---|---|---|
| < 28 Bit | 0 | `weak` | `bg-red-500` |
| 28–35 Bit | 1 | `fair` | `bg-orange-500` |
| 36–59 Bit | 2 | `good` | `bg-yellow-500` |
| 60–79 Bit | 3 | `strong` | `bg-green-500` |
| ≥ 80 Bit | 4 | `veryStrong` | `bg-emerald-500` |

**Rückgabe:**
```typescript
interface PasswordStrength {
    score: 0 | 1 | 2 | 3 | 4;
    label: string;
    color: string;
    entropy: number; // gerundet
}
```

---

## Standard-Optionen

| Option | Wert |
|---|---|
| `DEFAULT_PASSWORD_OPTIONS` | Länge 16, alle Kategorien aktiv |
| `DEFAULT_PASSPHRASE_OPTIONS` | 4 Wörter, Separator `-`, kapitalisiert, mit Zahl |

---

## Hilfsfunktionen (intern)

### `getSecureRandomChar(str): string`
Zieht ein zufälliges Zeichen aus einem String via `getSecureRandomInt()`.

### `getSecureRandomElement<T>(arr): T`
Zieht ein zufälliges Element aus einem Array via `getSecureRandomInt()`.

### `getSecureRandomInt(min, max): number`
Generiert eine kryptographisch sichere Zufallszahl im Bereich `[min, max]`.

**Ablauf:**
1. Berechnet `range = max - min + 1`
2. Bestimmt benötigte Bytes: `ceil(log₂(range) / 8)`
3. Berechnet `maxValid` für **Modulo-Bias-Eliminierung**: `floor(256^bytesNeeded / range) × range - 1`
4. Generiert zufällige Bytes in einer **Rejection-Sampling-Schleife** bis `randomValue ≤ maxValid`
5. Gibt `min + (randomValue % range)` zurück

> **Wichtig:** Diese Methode eliminiert Modulo-Bias, was bei `Math.random() % range` nicht der Fall wäre.

### `shuffleArray<T>(array): void`
Fisher-Yates-Shuffle mit `getSecureRandomInt()`. Mutiert das Array in-place.
