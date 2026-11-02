---
title: "Merkle Tree Certificates Deployment Use Cases"
abbrev: "MTC Use Cases"
category: info

docname: draft-ietf-plants-mtc-deploy-use-cases-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "PKI, Logs, And Tree Signatures"
keyword:
 - Merkle Tree Certificate
 - Post Quantum
 - PKI
venue:
  group: "PKI, Logs, And Tree Signatures"
  type: "Working Group"
  mail: "plants@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/plants"
  github: "ietf-plants-wg/deploy-use-cases"
  latest: "https://github.com/ietf-plants-wg/deploy-use-cases/draft-ietf-plants-mtc-deploy-use-cases.html"

author:
 -
    ins: J. Gray
    name: John Gray
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: john.gray@entrust.com
 -
    ins: J. Klaussner
    name: Jan Klaussner
    org: Bundesdruckerei GmbH
    email: jan.klaussner@bdr.de
    street: Kommandantenstr. 18
    code: 10969
    city: Berlin
    country: Germany
 -
    ins: L. Tindell
    name: Luke Tindell
    org: UK National Cyber Security Centre
    email: luke.t2@ncsc.gov.uk
    country: United Kingdom
 -
    ins: G. Mallaya
    name: Ganesh Mallaya
    org: AppViewX Inc
    abbrev: AppViewX Inc
    street: 107 Spring Street
    city: Seattle, Washington
    country: USA
    email: ganesh.mallaya@appviewx.com


normative:
   I-D.ietf-plants-merkle-tree-certs:

informative:
   I-D.draft-gray-plants-mtc-ldp:

...

--- abstract

Merkle Tree Certificates (MTCs)

{{I-D.ietf-plants-merkle-tree-certs}} has been defined for the
use case of the WebPKI.  In this document we explore when and how MTCs
in parts or full can be used in different use cases. Some of these
use-cases may provide benefit for private PKI usage.

--- middle

# Introduction

Merkle Tree Certificates (MTCs) have been designed to solve two problems for the WebPKI:

1. **Size.** A *landmark-relative Merkle Tree Certificate* is small as it
  only contains a public key and a small Merkle Tree inclusion proof.
2. **Downgrade Detection.** MTCs ensures Certificate Transparency is post-quantum secure, and with that
   allows detection of post-quantum downgrade attacks.

Besides solving these two problems, MTCs has additional benefits.

**Batch Signing.** MTCs reduces the load on the CA because a single signature is used for a batch of certificates.

A PKI that operates with any of these three challenges could benefit from MTC.
These advantages come with trade-offs:

1. The small *landmark-relative* MTCs can only be used if the verifier
   has been updated with recent *landmarks*. If the verifier is stale, it
   has to fall back to a larger *standalone* MTC or it will need a
   mechanism to be able to fetch the latest landmarks (refresh its
   state). The prover and verifier need a mechanism to negotiate whether
   to use the landmark-relative or standalone certificate.
2. For downgrade detection, the issuer needs to publish a log of issued
   certificates.
3. Batch sizing parameters will need to be carefully chosen to optimize
   system efficiency based on the particular use-case.

## Brief overview of MTCs

A Merkle Tree Certificate is a regular X509 certificate with two
differences:

1. Instead of a single signature, an MTC can contain zero or more signatures:
   zero in the case of landmark-relative and one-or-more in case of standalone.
   One is by the issuer, and others are added when certificate transparency is required.
2. The contents of the certificate is not signed directly, but instead
   a Merkle tree head is signed, together with providing a proof-of-inclusion
   of the certificate contents in that Merkle tree.

The use of a Merkle tree allows for batch signing, and the cost of a signature is
amortized over the number of certificates at the leaf notes.

If a verifier has out-of-band knowledge of the treehead used (which in
that case is called a *landmark*), then it can be satisfied with
the landmark-relative certificate that leaves out the signatures.

##To MTC or not to MTC

Using Merkle Tree Certificates (MTCs) is a change to PKI infrastructure that
comes with potential benefits but will incur other overheads, it is worth
considering both before a transition.

MTCs are an alternative mechanism to certificate chains. They allow a relying
party to validate that a certificate chains back to a trust anchor in its root
store. MTCs do not replace a leaf certificate's public key or the need for the
authenticating party to prove possession of the corresponding private key.
While MTCs can reduce the certificate chain overhead, they cannot address PKIs
where a public key and a signature are themselves too large.

Reducing the authentication overhead is one of the main motivations for using
MTCs. Therefore MTCs should be compared against alternative approaches that
achieve similar savings such as pre-distributing intermediate certificates. If
a relying party has a local copy of the intermediate certificate, then the
authenticating party needs to only send the leaf certificate without the rest
of the certificate chain. The size comparison is therefore between the
authentication overhead to validate the leaf certificate in each scenario.

A leaf certificate requires a signature for validation, while a landmark-relative
MTC requires an inclusion proof and a standalone MTC requires both an inclusion
proof and a signature. The relying party has to have acquired an authenticated
landmark to accept landmark-relative MTCs and so any gains due to the size
difference between an inclusion proof and a signature can only be realised if
a PKI can effectively distribute landmarks to the relying parties. If there are
relying parties within a PKI who cannot update their landmarks then those relying
parties need to handle standalone certificates for every connection. PKIs can
consider the likely proportion of connections that will use each MTC certificate
type based on how well they can pre-distribute the landmarks.

For PKIs that do not require certificate transparency, it is not necessary to
introduce it to use MTCs. PKIs can omit the additional cosignatures, and use a
single signature over the landmark from the CA. Where a PKI does require
certificate transparency, the transparency signature material should be included
in the size comparisons for leaf certificates, standalones and landmark-relative
MTCs as they improve the relative size savings of landmark-relative MTCs drastically.

Another motivation to use MTCs is to reduce the load on a CA as a single signature
can be used for a batch of certificates, amortizing the cost over the number of
certificates at the leaf nodes. The size of these batches comes with trade-offs
against the size of the certificates. See batch size trade-offs discussion below
for more details.

One potential downfall for MTCs is the availability concerns of a system that
distributes the signed landmarks to relying parties; this needs to be highly
available to the relying parties within a PKI as an extended period of downtime
could become a single point of failure within the PKI. Pre-distribution of
intermediate certificates only needs to be done faster than the rate of
intermediate certificate lifetimes, while pre-distribution of landmarks needs
to be done faster than the rate of leaf certificate lifetimes.

## Batch size trade-offs

A PKI can make trade-offs when selecting MTC batch sizes for both
checkpoints and landmarks.

For checkpoints the trade-off is between computational cost of signatures and
the size of standalone certificates. Smaller checkpoint batches require more
frequent signatures, but reduce the size of the inclusion proofs for standalone
certificates. Conversely, larger batches reduce the signature frequency but
increase the size of inclusion proofs for standalone certificates.

For landmarks the trade-offs are between relying party storage costs and the
size of landmark-relative certificates. Fewer landmarks require less storage on
the relying party, but result in each landmark representing a larger Merkle
tree, which increases the size of the inclusion proof for the landmark-relative
certificate. Conversely, more frequent landmarks would give smaller proofs for
the landmark-relative certificate but require more storage on the relying party.

Both batch sizes will be influenced by the specifics of the PKI, including the
frequency of certificate signing requests and acceptable issuance latency.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Use cases

## Verification of LandMark-Relative Merkle Tree Certificates outside the WebPKI

Merkle Tree Certificates which only contain the inclusion proof
to a signed tree head can only be verified when the verifier contains the
landmark that completes the inclusion proof contained in the Certificate
signature field.  If the certificate is in a non webPKI environment where it has an
online connection it should be possible for the verifier to request a refresh
of its landmarks.  There are different ways this can be accomplished:

1. It can be done dynamically, on demand by the verifier.  A mechanism
   that fetches landmarks from a distribution location could be added to
   the certificate which could be used to complete this lookup.  Such a
   mechanism could be similar to an X.509 CRLDP, except in this case it
   could be a "Landmark Distribution Point".

2. The landmarks could be fetched periodically by the verifier (or a
   distribution system could push them down to the verifiers).

3. They could be fetched by a locally defined policy.  For example they
   could be pre-shared at a location governed by a local policy.


### Landmark Distribution Point Fetching Mechanism

The Landmark Distribution Point (LDP) mechanism for retrieving consistency
proofs and validating landmark-relative certificates is specified in
{{I-D.draft-gray-plants-mtc-ldp}}.

## Batching for performance optimization

**When**
Signatures are expensive computational operations.  Systems where
high signature throughput is important are good candidates for the use
of batch signing, as it can provide a sizeable performance optimization
(for example, device certificates).  Merkle Trees with leaves of size N
can be computed as hashes of the toBeSigned data, with a single signature
over the root of that Merkle Tree.  For example, a Merkle tree of size
2^12 would have 2^11 leaves and could represent 2048 signatures.  The
verifier would only need to create a single signature for each batch
of 2048 toBeSigned data values.  Larger sizes could be used to meet the
operational requirements of the system.

**Requirements**
The verifier could use the mechanism defined in "Verification of
signatureless Merkle Tree Certificates" above to verifiy the signature
when certificates are used.

TODO:  If a certificate is not used, the same kind of fetching mechanism
would be needed for the verifier but that would need to be provided by
some out-of-band mechanism.



## Just using transparency
TODO - discuss advantages of transparency logs
- Track mis-issued certificates in your private key
- CA's already have an audit trail - is there an advantage to using transparency logs
- Need a source of truth for cross checking


## Certificate Revocation
If a certificate is compromised, mis-issued or no longer trustworthy, revocation is
a mechanism that allows a certificate to be declared invalid.  It is a critical part
of RFC 5280 path building, and is required to support long-lived certificates in a
private PKI infrastructure.

The two main types of revocation in use today are Certificate Revocation Lists (CRLs)
and OCSP (On-line certificate status Protocol).  A Certificate Revocation List (CRL)
is a digitally signed list published by a CA that identifies certificates that have
been revoked and should no longer be trusted before their expiration date.  Over time
they become large and stale, and require periodic download leading to increased
bandwidth, latency and delayed revocation awareness. OCSP creates individual proofs
for each certificate, requiring an updated signature for every updated request or
change in status of a certificate revocation.  In the context of much larger PQ
signatures like ML-DSA, a single revocation check increases from about 400 bytes to
around 4kb, which is 8 to 10 times larger!

Merkle Tree-based revocation can be significantly more efficient than CRL and OCSP by
effectively using small cryptographic proof sizes along with batch signing.  For
example, in OCSP each proof is signed, in Merkle Tree Revocation, each proof becomes
a leaf-hash in the Merkle Tree.  A relying party only needs a small cryptographic
proof, typically logarithmic in the number of certificates, rather than downloading
an entire revocation list or contacting an online responder for each validation. This
reduces bandwidth consumption, eliminates dependence on highly available OCSP
infrastructure, and enables offline verification. As the number of revoked
certificates grows, Merkle proofs remain compact and scalable, making them
particularly attractive for large PKI deployments and post-quantum environments where
revocation artifacts and signatures may be substantially larger.


## Code Signing and Software Supply Chain Integrity

The verification model for code signing differs fundamentally from TLS.  In a TLS
handshake, the server is present at verification time and format negotiation between
prover and verifier is possible.  A signed artifact is a static object: a binary,
container image or firmware update is signed once and subsequently verified at
deployment or execution time, potentially on a system with no network access and
potentially years after the signing event.  No live channel exists between the signer
and the verifier at the time of verification.

This distinction has a direct consequence for MTC deployment in code signing contexts.
Landmark-relative certificates require the verifier to hold a cached landmark at the
time of verification.  A verifier operating on an air-gapped system, or validating an
artifact whose issuing CA has since been decommissioned, cannot be assumed to maintain
a current landmark cache.  Standalone MTCs SHOULD be used for code signing artifacts.
A standalone MTC carries the CA signature inline and can be verified using only the CA
public key held as a locally-configured trust anchor, with no network access required.

The certificate size reduction that motivates landmark-relative certificates in TLS is
not a meaningful consideration in code signing.  A post-quantum CA signature embedded
in a binary of tens to hundreds of megabytes represents negligible overhead.

### Batch Signing for Code Signing Certificate Authorities

A code signing CA serving a large enterprise or a high-throughput CI/CD environment
may issue signing certificates at a volume that places real throughput demands on its
signing infrastructure.  With post-quantum signature algorithms, the per-operation
signing cost increases relative to classical algorithms.  MTC batch signing amortizes
this cost: the CA constructs a Merkle tree over a batch of certificate requests,
produces a single signature over the tree root and issues each certificate with its
inclusion proof.  The number of CA signing operations is reduced by a factor equal to
the batch size, independent of the algorithm used to produce the root signature.

Code signing CAs SHOULD select batch sizes with reference to peak certificate issuance
volume and acceptable issuance latency.  Guidance on batch size trade-offs is provided
in Section 1.2 of this document.

### The Case for Transparency in Private PKI Code Signing

Private PKI code signing operates without any transparency requirement today.
Certificates issued by an enterprise CA for signing purposes are not recorded in any
independently accessible log.  This differs from Web PKI TLS certificates, which must
be disclosed to public Certificate Transparency logs as a condition of browser trust.
Code signing certificates issued by public CAs are also outside the scope of existing
Certificate Transparency requirements.

The absence of transparency creates a specific structural vulnerability.  A CA audit
database is an asset under the administrative control of the PKI operator.  An attacker
who has obtained administrative access to the CA, or a privileged insider, can issue
signing certificates to unauthorized entities and subsequently modify the audit database
to suppress evidence of those issuances.  Because the CA and its audit database share
an administrative boundary, the audit database does not constitute an independent check
on CA behavior.

An MTC transparency log operated independently from the issuing CA addresses this gap.
The Merkle-tree structure of the log means that once a batch tree head is signed and
published, any modification to prior log entries breaks the cryptographic chain.  An
independent party retaining a copy of published tree heads at any point can detect
subsequent modification.  This property holds even when the CA infrastructure is
subsequently compromised, because the log operator and the CA operator are separate
administrative entities.

Recent software supply chain compromises have followed this pattern: the signing
certificate was valid, the artifact signatures were valid and no PKI mechanism existed
to detect anomalous signing activity prior to discovery through behavioral indicators.
An independently operated transparency log changes this property.  Any use of a
compromised or fraudulently issued signing certificate produces a record that cannot
be erased without detection by any party that has retained log state.

### Transparency Log Requirements for Code Signing

Transparency logging can make signing activity independently verifiable and support
incident investigation.  Deployments need to decide what issuance metadata to record,
how artifacts refer to their log entries, and how algorithm transitions are recorded.
Deployments may use an artifact-associated receipt to identify the relevant log entry.

### Independent Monitor

An independent monitor can compare logged issuance against authorization and migration
policies, then alert on unexpected entities, algorithm downgrades, or other anomalous
activity.  Separation between the monitor and CA administration provides an independent
check.  Monitoring can focus on unauthorized issuance, algorithm downgrades, and other
anomalous activity.

### Archival Obligations

Signed artifacts may need to be verified long after issuance, including after the issuing
CA has been decommissioned.  Deployments therefore need an archival plan for log data and
published tree heads for an appropriate period, including after the issuing CA has been
decommissioned.


## Private PKI PQC Migration with Downgrade Resistance

The first post-quantum cryptographic algorithm standards were published by NIST in 2024,
including ML-DSA (FIPS 204), ML-KEM (FIPS 203) and SLH-DSA (FIPS 205).  Enterprises
operating private PKIs are under increasing regulatory pressure to migrate from classical
algorithms.  This migration cannot be completed instantaneously.  A private PKI
environment typically includes endpoints with varying post-quantum readiness, and some
endpoints may be incapable of post-quantum algorithm support for their operational
lifetime.  The period during which both classical and post-quantum certificates are
simultaneously in active use is the hybrid transition period.

The hybrid transition period creates attack opportunities that do not exist in a fully
migrated environment.  This section describes those threats and the capabilities MTC
provides to detect them.

### Active Downgrade During Hybrid Deployment

When a server holds a post-quantum certificate and also supports classical algorithm
fallback for legacy clients, a network-positioned adversary may suppress post-quantum
algorithm negotiation during connection establishment.  The server completes the
connection using classical algorithms.  Both endpoints complete the exchange without
error and neither endpoint produces any observable indication that the negotiated
algorithm set differs from what the server would prefer.

In Web PKI, mechanisms such as strict transport security and browser-enforced algorithm
policy provide partial protection against this class of attack.  Private PKI
deployments, including internal service communication, enterprise VPN infrastructure
and industrial protocol endpoints, do not benefit from equivalent enforcement
mechanisms.  Classical fallback paths persist in private PKI environments for as long
as any endpoint requires classical support, and an adversary aware of this fact can
exploit those paths selectively and systematically.

MTC transparency provides post-hoc detection capability for this threat.  When the
transparency log records that a server held a post-quantum certificate during a given
period and operational logs from that period show only classical algorithm connections
to that server, this discrepancy constitutes evidence of systematic downgrade.  The
transparency record does not prevent the downgrade in real time, but it enables
detection and scoping of the compromise through records maintained independently of
the endpoints involved.

### Harvest Now Decrypt Later

Adversaries may record encrypted private PKI traffic with the intent to decrypt it
when quantum computing capabilities become sufficient.  For communications whose
confidentiality requirements extend beyond the expected availability of a
cryptographically relevant quantum computer, traffic captured today represents a
future liability.  Private PKI protects communications that may retain sensitivity
for a decade or more: personnel records, financial transactions, intellectual property
and industrial control system telemetry.  The effective migration deadline for such
data is not solely the date of quantum computer availability, but the date by which
the protected data will have lost its sensitivity.

The MTC transparency log does not prevent traffic capture.  It provides a verifiable
record of when post-quantum algorithm adoption occurred across the PKI, enabling an
organization to demonstrate with cryptographic verifiability that sensitive
communications were protected by post-quantum algorithms from a documented date.
This record is relevant to regulatory compliance frameworks that require evidence of
completed migration rather than assertions about future intent.

### Unauthorized Classical Certificate Issuance During Migration

During a hybrid transition, an entity that has moved to post-quantum algorithms may still
receive a classical certificate through policy error or unauthorized issuance.  A
transparency log and independent monitor comparing issuance records with migration status
can detect this mismatch and alert PKI operators.

### Frozen Devices

Certain devices in private PKI environments cannot receive updates that would add
post-quantum algorithm support.  Regulatory re-approval requirements, sealed hardware
and immovable service constraints mean that some endpoints will continue to use
classical algorithm certificates for the duration of their service lives, regardless
of the broader migration status of the PKI.
These devices need not implement MTC.  A transparency log and independent monitor can
identify unexpected issuance for this population without requiring changes to device
firmware or software.  The monitor can compare issuance against the operator's approved
device and issuer information.

### Algorithm Metadata Requirements

For the transparency log to support the use cases described in this section, the log
needs to capture the algorithms used for batch signatures and certificates.  Recording
algorithm transitions also supports auditing of migration progress.

### Migration Staging

A private PKI operator deploying MTCs during the post-quantum transition period should
establish issuance visibility, move through hybrid operation toward post-quantum-only
issuance, and account for devices that cannot migrate.  Appropriate stages and their
duration depend on endpoint readiness and organizational requirements.


## Constrained Device Certificate Validation

Private PKI deployments include endpoint populations with constraints on available
memory, processing capacity and network access.  Access control readers validating
employee identity credentials, sensors on isolated operational technology networks
and embedded controllers in long-lived infrastructure may need to validate
certificates issued over an extended time window, potentially spanning years, without
the ability to maintain a continuously updated landmark cache or retrieve landmarks
on demand.

Unlike online landmark distribution, this use case considers endpoints that cannot
reliably retrieve or continuously refresh landmark information.  Deployments need to
balance storage, connectivity, and the ability to recover safely after an extended
offline period.

### The Landmark Accumulation Problem

In a traditional X.509 deployment, a constrained verifier typically holds one or more
trust anchor certificates and retrieves revocation data periodically.  Each CRL
supersedes its predecessor and the verifier need not retain prior revocation data.
Storage requirements are bounded and predictable.

With MTC, a verifier may need to retain landmarks corresponding to certificates it
validates.  Storage needs therefore depend on the validation window and landmark
publication frequency.  PKI operators should consider the capacity of the most
constrained device when selecting a publication schedule.

### Landmark Rebasing

Landmark rebasing may reduce the number of landmarks a constrained device must retain
by replacing multiple older landmarks with a more compact representation.  Devices need
a way to establish trust in the replacement before discarding the landmarks it covers.

### Re-anchoring After Extended Offline Periods

A device that has been without network access for an extended period accumulates a
deficit of landmarks issued during its offline interval.  Upon reconnecting, the
device must obtain those landmarks before it can validate certificates issued during
the offline period.

When connectivity returns, the device needs to catch up efficiently and avoid accepting
stale landmark information.  The deployment must account for both recovery bandwidth
and the device's ability to retain trusted state across restarts.  Devices also need to
avoid accepting stale landmark information when reconnecting.

### Guidance for PKI Operators

PKI operators SHOULD document landmark publication schedules and storage expectations
for constrained populations.  They SHOULD also describe any rebasing or recovery
procedures that are part of the deployment.

Where a PKI serves both constrained and non-constrained populations, operators may
consider separate landmark schedules or distribution methods.  Non-constrained devices
can obtain landmarks online, while constrained devices may receive them through an
out-of-band channel, with updates validated against the device's previously trusted
landmark state.


# Security Considerations

TODO Security


# IANA Considerations

This document requests a new id-pe-ldpBaseURIs extension for use with X.509 certificates
in the "SMI Security for PKIX Certificate Extension" registry (1.3.6.1.5.5.7.1).

--- back

# Acknowledgments
Thanks to David Benjamin, Bas Westerbaan, Mike Ounsworth, Tirumaleswar Reddy, Rich Salz and Kris Kwiatkowski for their feedback and review of this specification.
