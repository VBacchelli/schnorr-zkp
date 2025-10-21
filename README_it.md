# Protocollo di Identificazione di Schnorr (Zero Knowledge Proof)

🇬🇧 - [Read in English](./README.md)

## Introduzione
Questo progetto è un’implementazione del protocollo di identificazione di Schnorr, un classico esempio di *Zero-Knowledge Proof of Knowledge* (ZKPoK).  
Dimostra come un *Prover* possa convincere un *Verifier* di conoscere un segreto $x$ tale che $y = g^x \bmod p $, senza rivelare il valore di $x$.

Il progetto è stato sviluppato come parte del corso **Sicurezza dell’Informazione M** dell’**Università di Bologna**, con l’obiettivo di mostrare un’implementazione pratica di un protocollo a conoscenza zero in Java.

## Contesto Teorico

Le *Zero-Knowledge Proofs* (ZKP) permettono a una parte (Prover) di convincere un’altra (Verifier) di conoscere un segreto, **senza rivelarne alcuna informazione**.  

Il protocollo di Schnorr, proposto da *Claus-Peter Schnorr (1990)*, è uno degli esempi fondamentali di ZKP.  
Si basa sulla difficoltà del **Problema del Logaritmo Discreto (DLP)** nei gruppi modulari, secondo cui, dati p, g e $y = g^x \bmod p$, è computazionalmente impraticabile ricavare $x$.

Il protocollo garantisce tre proprietà:
- **Completezza**: un prover onesto convince sempre un verifier onesto.  
- **Solidità (Soundness)**: un prover disonesto non può convincere il verifier senza conoscere $x$.  
- **Zero-Knowledge**: il verifier non apprende nulla su $x$ oltre al fatto che il prover lo conosce.

## Struttura del Progetto
| Package | Descrizione                                             |
| ------- | ------------------------------------------------------- |
| `model` | Strutture dati (`Parameters`, `KeyPair`, `Proof`)       |
| `core`  | Logica centrale del protocollo (`Prover`, `Verifier`, `Simulator`) |
| `util`  | Utility crittografiche (random, helper)                 |
| `app`   | Punto di ingresso della demo (`Main.java`)              |
| `test`  | Suite di test JUnit (soundness, tentativi di forgiatura) |

## Passaggi del Protocollo
**Setup**: i parametri pubblici ($p$, $q$, $g$) definiscono un sottogruppo di $ℤ^*_p$ di ordine $q$.

**Generazione delle chiavi**:

- Chiave privata: $x ∈ Z_q$  
- Chiave pubblica: $y = g^x \bmod p$

**Round di identificazione**:

- Il `Prover` sceglie un valore casuale $k$ e invia $r = g^k \bmod p$.  
- Il `Verifier` invia una sfida casuale $c$.  
- Il `Prover` risponde con $s = (k + c·x) \bmod q $.  
- Il `Verifier` verifica che $g^s ≡ r·y^c \bmod p $.

Se l’uguaglianza è soddisfatta, il verifier è convinto che il prover conosca $ x $.

## Panoramica dell’Implementazione

### `Parameters.java`
Definisce i parametri pubblici ($p$, $q$, $g$) del protocollo.
- `generate(int bits)`: genera in modo sicuro un set valido di parametri, garantendo che $q \mid (p−1)$ e che $g$ abbia ordine esattamente $q$.  
- `demo()`: genera piccoli valori leggibili (insicuri, per test).  
- `randomZq()`: genera un numero casuale uniforme in $Z_q$.  

Questi parametri definiscono il gruppo algebrico su cui operano tutte le operazioni.

### `KeyPair.java`
Rappresenta la coppia di chiavi del prover ($x$, $y = g^x \bmod p $).  
La chiave segreta $ x $ è salvata come `byte[]` e convertita in `BigInteger` solo quando necessario.

- `multiplySecret(BigInteger value)`: calcola $(x \cdot value) \bmod q $ senza esporre $ x$.  
- `matchesSecret(BigInteger candidate)`: verifica se un valore corrisponde alla chiave privata (usato nei test di soundness).  

Non esiste un getter pubblico per la chiave privata, che rimane confinata nella classe.

### `Prover.java`
Gestisce il lato del prover:
- `generateCommitment()`: genera un nonce casuale $k$ e calcola$ r = g^k \bmod p $.  
- `respondToChallenge(BigInteger c)`: calcola $ s = (k + c·x) \bmod q $ e costruisce un `Proof(r, c, s)`.  

Il nonce $k$ è rigenerato a ogni esecuzione e mai riutilizzato.

### `Verifier.java`
Implementa la verifica:
- `generateChallenge()`: genera una sfida casuale $c ∈ Z_q$.  
- `verify(Proof proof, BigInteger publicKey)`: verifica $g^s ≡ r·y^c \bmod p $.  

Restituisce `true` se la prova è valida, `false` altrimenti.

### `Simulator.java`
Illustra la proprietà di *zero-knowledge*:
- `simulateProof()`: genera un transcript falso ma valido ($r, c, s$) senza usare alcuna chiave privata.  
  Dimostra che il verifier non può distinguere le prove simulate da quelle reali.

### `Proof.java`
Semplice classe immutabile che contiene:
- `r`: commitment  
- `c`: challenge  
- `s`: response  

Serve come contenitore di scambio tra prover e verifier.  
Il suo `toString()` stampa i valori in esadecimale per leggibilità.

### `Main.java`
Esegue una dimostrazione completa del protocollo:

1. Genera i parametri ($p$, $q$, $g$ ).  
2. Crea una `KeyPair` per il `Prover`.  
3. Inizializza `Prover` e `Verifier`.  
4. Esegue un round completo di identificazione:
   - Il prover invia `r`
   - Il verifier invia la sfida `c`
   - Il prover risponde con `Proof(r, c, s)`
   - Il verifier verifica e stampa il risultato

## Test
La suite di test JUnit5 verifica tutte le principali proprietà teoriche del protocollo di Schnorr:  
**completezza**, **soundness** e **zero-knowledge**, oltre a un test di robustezza contro prove non valide.

- **`testProtocolVerification()`** — verifica la completezza: un prover e un verifier onesti devono sempre riuscire.  
- **`testSoundnessViaRewinding()`** — mostra la *soundness* tramite *rewinding*: due prove valide con la stessa $r$ ma sfide diverse permettono di estrarre $x$.  
- **`testZeroKnowledge()`** — verifica la proprietà *zero-knowledge*: le prove simulate senza la chiave privata vengono comunque accettate.  
- **`testInvalidProof()`** — controlla la robustezza: le prove modificate o corrotte vengono rifiutate.

## Esecuzione della Demo
```bash
./gradlew run
```

oppure, da Eclipse:

Run → Main.java

Esempio di output:
```
=== Schnorr Zero-Knowledge Proof Demo ===

[Parameters]
Parameters {
  p = 508150370065779801213387943141503126563,
  q = 254075185032889900606693971570751563281,
  g = 424030122054390383955382977622240861779
}

[Key Pair]
KeyPair {
  (private key hidden),
  y (public) = 200947051474585436195635815030571466181
}

[Prover → Verifier] Commitment r = 17883297947470169822363002634013789875

[Verifier → Prover] Challenge c = 210218893716285914523563881504252794249

[Prover → Verifier] Proof = Proof {r=d7432a9b700ad77bd49375a6da44eb3, c=9e26afacaa5934018ae9b763c1f29589, s=51b3bf35cb8a64dcd715e6e670677f68}

[Verifier] Verification result: ACCEPTED
```

## Note di Sicurezza
**Casualità crittograficamente sicura**  
Tutti i valori segreti ($x$, $k$, $c$) sono generati con `SecureRandom`, che assicura numeri casuali adatti a uso crittografico e previene il riuso di $k$, una causa comune di compromissione della chiave segreta.

**Correttezza della generazione dei parametri**  
Il generatore $g$ è costruito in modo da avere ordine esatto $q$ in $ℤ^*_p$, evitando attacchi basati su sottogruppi minori. Questo garantisce che tutte le prove operino nel sottogruppo corretto e che il protocollo mantenga le sue proprietà di sicurezza.

**Gestione della chiave privata**  
La chiave segreta $x$ è memorizzata internamente come `byte[]` e mai esposta o stampata.  
Le operazioni che la coinvolgono sono confinate nella classe `KeyPair` attraverso i metodi `multiplySecret()` e `matchesSecret()`, riducendo al minimo il rischio di perdite accidentali.

**Scopo educativo**  
Questa implementazione è destinata a fini accademici e dimostrativi.  
Non è progettata per l’uso in produzione o in ambienti che richiedano sicurezza crittografica reale.

## Licenza

Questo progetto è rilasciato sotto licenza MIT, una licenza open source permissiva che consente di utilizzare, modificare e distribuire liberamente il codice, anche per scopi commerciali, a condizione che venga mantenuto il copyright originale.
Per i termini completi, consultare il file [LICENSE](./LICENSE).
