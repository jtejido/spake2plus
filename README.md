# spake2plus

[**RFC**](https://tools.ietf.org/id/draft-bar-cfrg-spake2plus-01.txt) 

SPAKE2+ has been detached from its joint definition in RFC standard with SPAKE2.
While SPAKE2 is used for peer-to-peer communication, SPAKE2+ is ideal for Client-Server Authentication.

From the current [RFC](https://tools.ietf.org/id/draft-bar-cfrg-spake2plus-01.txt): 

**SPAKE2+** is an augmented PAKE protocol, as only one party (Client/A) makes direct use of the password during 
the execution of the protocol.  The other party (Server/B) only needs a verification value at the time of the 
protocol execution instead of the password.

**SPAKE2+ Trace:**

```
                  A                           B

                  |         (Preamble)        |
                  |<- - - - - - - - - - - - ->|
                  |                           |
                  |       (setup protocol)    |
     (compute pA) |             pA            |
                  |-------------------------->|
                  |             pB            | (compute pB)
                  |<--------------------------|
                  |                           |
                  |       (derive secrets)    | (compute cB)
                  |             cB            |
                  |<--------------------------|
     (compute cA) |             cA            |
                  |-------------------------->|
```

SPAKE2+ is a two round protocol that establishes a shared secret with an additional round for key confirmation.
The Preamble part (suite and h2c definition, etc., used by both server and client) is beyond the scope of the RFC, and so is this repo. 

The *Client* and *Server* instance will have to assume that the other party uses the same.

The Registration part in test is part of the *Preamble Exchange* where the verifier materials and Identity will be sent and stored by the server on a non-volatile DB. This exchange part of the protocol had to be secured by both parties and not defined in RFC.

The lookup DB provided here is just an in-memory K-V map.

This is only a benchmark/study for SPAKE2+ that closely follows the most recent RFC with all the recommended CipherSuites.


Dependencies:

1. Cloudflare's [CIRCL](https://github.com/cloudflare/circl) - For P384 (amd64) and Ed448 

2. Scrypt and Argon2id are given as MHF options. (see spake2.go)


To-Do:

1. Context

## Disclaimer

**!!DON'T USE THIS IN PRODUCTION!!**

This is used for benchmarking all suites. RFC changes over time.
Moreover, Golang's P384 and P521 aren't constant time, so is big.Int, and I also cannot vouch for the stability of the dependencies listed here.


## Benchmark

```
goarch: amd64
pkg: github.com/jtejido/spake2plus
BenchmarkSPAKE2PlusEd25519Scrypt-4                   722           1648622 ns/op
BenchmarkSPAKE2PlusEd448Scrypt-4                     298           4146113 ns/op
BenchmarkSPAKE2PlusP256Sha256Scrypt-4                576           1999250 ns/op
BenchmarkSPAKE2PlusP384Sha256Scrypt-4                129           9088915 ns/op
BenchmarkSPAKE2PlusP256Sha512Scrypt-4                624           2063409 ns/op
BenchmarkSPAKE2PlusP384Sha512Scrypt-4                128           9129860 ns/op
BenchmarkSPAKE2PlusP521Sha512Scrypt-4                 10         104200010 ns/op
PASS
```
