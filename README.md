# Proverif_QRAS-IoD

Formal security verification of **QRAS-IoD** with ProVerif.

This repository contains the ProVerif model and the verification results used in the security analysis of the paper:

> **Quantum-safe and Robust Authentication and Key Agreement Scheme for PUF-enabled Internet of Drones**
> (Joonyoung Lee, Sungjin Yu, and Kisung Park)

The ProVerif model checks, for an unbounded number of sessions, whether a Dolev–Yao adversary who fully controls the public channel and who may additionally steal the user's mobile device or physically capture a drone can break the secrecy of the identities, the password, and the session key, or the mutual authentication among the mobile user, the ground station server, and the drone.

---

## Table of Contents

1. [Protocol Overview](#protocol-overview)
2. [Repository Structure](#repository-structure)
3. [Requirements](#requirements)
4. [Reproducing the Analysis](#reproducing-the-analysis)
5. [ProVerif Model](#proverif-model)
6. [Security Queries](#security-queries)
7. [Results](#results)
8. [Scope and Limitations](#scope-and-limitations)
9. [Citation](#citation)
10. [References](#references)

---

## Protocol Overview

QRAS-IoD is an authentication and key agreement (AKA) scheme that combines **ML-KEM** (FIPS 203) with a **physical unclonable function (PUF)** embedded in each drone.

| Entity | Symbol | Role in the protocol |
|---|---|---|
| Mobile user | `MUi` | Starts the AKA phase and encapsulates a shared secret under the GSS public key |
| Ground station server | `GSS` | Trusted registration authority; relays and verifies messages between user and drone |
| Drone | `Dj` | Reconstructs its secret response `Rj = PUF(Cj)` on demand and derives the session key |

The AKA phase exchanges four messages over a public channel:

| Message | Direction | Content |
|---|---|---|
| `Msg1` | `MUi → GSS` | `{ct1, M1, M2, V1, TIDi, T1}` |
| `Msg2` | `GSS → Dj` | `{M3, V2, T2}` |
| `Msg3` | `Dj → GSS` | `{M4, V3, V4, T3}` |
| `Msg4` | `GSS → MUi` | `{M5, V4, V5, T3, T4}` |

Both ends derive the session key `SK = h(PIDi ‖ IDDj ‖ N1 ‖ N2 ‖ N3)`.

---

## Repository Structure

```
Proverif_QRAS-IoD/
├── code/
│   └── QRAS-IoD.pv        # ProVerif model of QRAS-IoD
├── result/
│   └── ProVerif           # Output of ProVerif (verification summary)
└── README.md
```

---

## Requirements

| Component | Purpose |
|---|---|
| [ProVerif](https://proverif.inria.fr/) 2.x | Automatic cryptographic protocol verifier in the symbolic (Dolev–Yao) model |
| [OCaml](https://ocaml.org/) and [opam](https://opam.ocaml.org/) | Only needed to build ProVerif from source on Linux/macOS |

On Windows, the pre-built binary distributed on the ProVerif website can be used instead of building from source.

---

## Reproducing the Analysis

### 1. Install ProVerif

On Linux/macOS, install it with opam:

```bash
opam install proverif
```

On Windows, download the binary package from <https://proverif.inria.fr/> and unpack it. The same page provides the user manual and the source distribution.

### 2. Get the model

```bash
git clone https://github.com/sungjinyu/Proverif_QRAS-IoD.git
cd Proverif_QRAS-IoD
```

### 3. Run ProVerif

```bash
proverif code/QRAS-IoD.pv
```

ProVerif prints the derivation of every query and ends with a `Verification summary` block. To keep the complete output:

```bash
proverif code/QRAS-IoD.pv > result/ProVerif
```

---

## ProVerif Model

The model is written in the typed applied pi-calculus input language of ProVerif and covers the drone registration, user registration, and AKA phases of QRAS-IoD. Every message and verification equation uses the same parameters as the paper; the mapping is listed in the header comment of `code/QRAS-IoD.pv`.

### Channels

```
free pub: channel.              (* public channel, fully Dolev-Yao controlled *)
free scDG: channel [private].   (* secure channel: Drone -> GSS (registration request) *)
free scGD: channel [private].   (* secure channel: GSS -> Drone (registration reply)   *)
free scGU: channel [private].   (* secure channel: User <-> GSS registration          *)
```

### Cryptographic primitives

| Primitive | ProVerif declaration | Abstraction |
|---|---|---|
| Hash `h(·)` | `fun h(bitstring): bitstring.` | One-way function without equations |
| Concatenation `‖` | `fun cat2(bitstring,bitstring): bitstring [data].` | Right-nested pairing |
| XOR `⊕` | `fun xor(bitstring,bitstring): bitstring.` | Cancellation law `xor(xor(x,y),y) = x` |
| PUF | `fun puf(bitstring): bitstring [private].` | Ideal, noise-free PUF that only the device can evaluate |
| ML-KEM | `pk`, `kemCt`, `kemKey`, `kemDecaps` | Idealised encapsulation/decapsulation |

```
equation forall x:bitstring, y:bitstring; xor(xor(x,y),y) = x.

fun pk(bitstring): bitstring.
fun kemCt(bitstring, bitstring): bitstring.
fun kemKey(bitstring, bitstring): bitstring [private].
reduc forall sk: bitstring, r: bitstring;
      kemDecaps(sk, kemCt(pk(sk), r)) = kemKey(pk(sk), r).
```

### Processes

| Process | Entity | Description |
|---|---|---|
| `DroneRegInit` | `Dj` | Drone registration: picks `rj`, `Cj`, computes `Rj = PUF(Cj)`, stores `{Fj, Gj}` |
| `GSSDroneReg` | `GSS` | Drone registration: computes `PIDDj`, `Gj`, stores `{PIDDj, (Cj, Rj)}` |
| `UserRegInit` | `MUi` | User registration: computes `RPWi`, stores `{Ci, D1, D2}` in the mobile device |
| `GSSUserReg` | `GSS` | User registration: computes `PIDi`, `Xi`, `Bi`, `Ci`, stores `{PIDi, Xi}` |
| `UserAKA` | `MUi` | Login check, `Msg1` generation, `Msg4` verification, session key derivation |
| `GSSAKA` | `GSS` | `Msg1`/`Msg3` verification, `Msg2`/`Msg4` generation |
| `DroneAKA` | `Dj` | `Msg2` verification, `Msg3` generation, session key derivation |
| `CorruptMD` | Adversary | Loss/theft of the mobile device |
| `CaptureDrone`, `PUFOracle` | Adversary | Physical capture of the drone |

The main process publishes `pkGSS` and runs an unbounded number of instances of every role in parallel:

```
process
    new skGSS: bitstring;
    let pkGSS = pk(skGSS) in
    out(pub, pkGSS);
    (
        (!DroneRegInit)               |
        (!GSSDroneReg(skGSS))         |
        (!UserRegInit(pkGSS))         |
        (!GSSUserReg(skGSS))          |
        (!GSSAKA(skGSS))
    )
```

### Adversary model

The adversary follows the **Dolev–Yao** model on the public channel `pub`: it can eavesdrop, intercept, modify, replay, delete, and inject messages. In addition, the model gives it the two device-compromise capabilities of the threat model:

```
(* Loss/theft of the mobile device: leaks the stored values {Ci, D1, D2} *)
let CorruptMD(Ci: bitstring, D1: bitstring, D2: bitstring) =
    event MDCorrupted(IDi);
    out(pub, (Ci, D1, D2)).

(* Physical capture of the drone: leaks the stored values {Fj, Gj} *)
let CaptureDrone(Fj: bitstring, Gj: bitstring) =
    event DroneCaptured(IDDj);
    out(pub, (Fj, Gj)).

(* The captured device can be queried as a PUF oracle *)
let PUFOracle =
    in(pub, c: bitstring);
    out(pub, puf(c)).
```

### Timestamp abstraction

A symbolic model has no clock, so the freshness checks `|T2 − T1| ≤ ΔT` and `|T3 − T2| ≤ ΔT` are abstracted. The current time of a verifier is a fresh value that the verifier makes public, and a message is accepted only if its timestamp equals that value:

```
(* GSS *)
new nowG: bitstring;
out(pub, (tagClkGSS, nowG));
in(pub, (ct1_r: bitstring, M1_r: bitstring, M2_r: bitstring, V1_r: bitstring,
         TIDi_r: bitstring, T1_r: bitstring));
if T1_r = nowG then ...
```

These clock broadcasts are not protocol messages; `Msg1`–`Msg4` keep the exact format of the paper.

---

## Security Queries

### Secrecy

| Query | Protected value |
|---|---|
| `query attacker(IDi).` | Real identity of `MUi` (user anonymity) |
| `query attacker(IDDj).` | Real identity of `Dj` (drone anonymity) |
| `query attacker(SK).` | Session key `SK` established between `MUi` and `Dj` |
| `query attacker(PWi).` | Password of `MUi`, also under mobile-device compromise |

Session-key secrecy is tested with a private marker `SK` that the drone and the user publish encrypted under the session key they actually computed (`out(pub, senc(SK, SK_d))`); the marker is derivable only if the adversary obtains one of those keys.

### Authentication

Each goal is expressed with a pair of events and checked as an injective correspondence (`inj-event`), which also rules out replay.

| Query | Property |
|---|---|
| `GSSAuthDrone(x,y) ==> DroneFinish(x,y)` | `GSS` authenticates `Dj` |
| `DroneAuthGSS(x,y) ==> GSSStartDrone(x,y)` | `Dj` authenticates `GSS` on `N2` |
| `GSSAuthUser(x,y) ==> UserStart(x,y)` | `GSS` authenticates `MUi` on `N1` |
| `UserFinish(x,y) ==> UserAuthGSS(x,y)` | `MUi` completes only after it has authenticated `GSS` |
| `UserFinish(x,y) ==> DroneFinish(z,y)` | `MUi` authenticates `Dj` on the session key `SK` |

```
query x:bitstring, y:bitstring; inj-event(GSSAuthDrone(x,y)) ==> inj-event(DroneFinish(x,y)).
query x:bitstring, y:bitstring; inj-event(DroneAuthGSS(x,y)) ==> inj-event(GSSStartDrone(x,y)).
query x:bitstring, y:bitstring; inj-event(GSSAuthUser(x,y))  ==> inj-event(UserStart(x,y)).
query x:bitstring, y:bitstring; inj-event(UserFinish(x,y))   ==> inj-event(UserAuthGSS(x,y)).
query x:bitstring, y:bitstring, z:bitstring; inj-event(UserFinish(x,y)) ==> inj-event(DroneFinish(z,y)).
```

---

## Results

ProVerif proves all nine queries:

```
--------------------------------------------------------------
Verification summary:

Query not attacker(IDi[]) is true.

Query not attacker(IDDj[]) is true.

Query not attacker(SK[]) is true.

Query not attacker(PWi[]) is true.

Query inj-event(GSSAuthDrone(x,y)) ==> inj-event(DroneFinish(x,y)) is true.

Query inj-event(DroneAuthGSS(x,y)) ==> inj-event(GSSStartDrone(x,y)) is true.

Query inj-event(GSSAuthUser(x,y)) ==> inj-event(UserStart(x,y)) is true.

Query inj-event(UserFinish(x,y)) ==> inj-event(UserAuthGSS(x,y)) is true.

Query inj-event(UserFinish(x,y)) ==> inj-event(DroneFinish(z,y)) is true.

--------------------------------------------------------------
```

The complete output is available in `result/ProVerif`.

---

## Scope and Limitations

The results hold in the symbolic model under the following abstractions:

- **Perfect cryptography.** The hash function and ML-KEM are idealised; computational bounds are addressed by the ROR-based proof in the paper, not by this model.
- **XOR.** Only the cancellation law `xor(xor(x,y),y) = x` is modelled; the other algebraic properties of XOR are not.
- **PUF.** The PUF is ideal and noise-free; fuzzy extractors and error correction are out of scope.
- **Timestamps.** Time-difference checks are abstracted by public clock values, as described above.
- **Password.** `attacker(PWi)` establishes that the password cannot be derived symbolically; offline guessing of low-entropy secrets is not modelled.
- **Compromise.** The adversary obtains `{Ci, D1, D2}` from a stolen mobile device and `{Fj, Gj}` plus PUF-oracle access from a captured drone. `GSS`, `skGSS`, and the drone key `DKj` are assumed uncompromised.

---

## Citation

If you use this repository, please cite the paper:

```bibtex
@unpublished{qras_iod,
  author = {Joonyoung Lee and Sungjin Yu and Kisung Park},
  title  = {Quantum-safe and Robust Authentication and Key Agreement Scheme for PUF-enabled Internet of Drones},
  note   = {Manuscript},
  year   = {2026}
}
```

---

## References

- ProVerif, cryptographic protocol verifier in the formal model: <https://proverif.inria.fr/>
- B. Blanchet, B. Smyth, V. Cheval, and M. Sylvestre, "ProVerif: Automatic Cryptographic Protocol Verifier, User Manual and Tutorial."
