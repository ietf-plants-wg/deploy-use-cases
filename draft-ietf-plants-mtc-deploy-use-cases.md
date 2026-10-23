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
I-D.draft-ietf-plants-merkle-tree-certs-03:

informative:

...

--- abstract

Merkle Tree Certificates (MTC)
I-D.ietf-plants-merkle-tree-certs has been defined for the
use case of the WebPKI.
In this document we explore when and how MTC in parts or full can be used in different
use cases. Some of this use-cases may provide benefit for private PKI usage.


--- middle

# Introduction

EdNote: Before getting into the nitty gritty, let's start with the potential benefit

Merkle Tree Certificates (MTC) have been designed to solve two problems for the WebPKI:

1. **Size.** A *landmark-relative Merkle Tree Certificate* is small as it
  only contains a public key and a small Merkle Tree inclusion proof.
2. **Downgrade Detection.** MTC ensures Certificate Transparency is post-quantum secure, and with that
   allows detection of post-quantum downgrade attacks.

Besides solving these two problems, MTC has additional benefits.

**Batch Signing.** MTC reduces the load on the CA because a single signature is used for a batch of certificates.

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

## Brief overview of MTC

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

   The ldpBaseURIs X509 V3 extension is held by the Issuer of the Signatureless
   Merkle Tree Certificate and contains the SEQUENCE of LandmarkDistributionPoints, each
   which is a LandmarkDistributionPoint of IA5String.  Each refers to a BaseURI location
   indicating where the landmarks are published.

~~~
id-pe-ldpBaseURIs OBJECT IDENTIFIER ::=  { id-pe TBD }

LandmarkDistributionPoints ::= SEQUENCE (1..MAX) OF LandmarkDistributionPoint

LandmarkDistributionPoint ::= IA5String
~~~


   The Inclusion Proof structure defined in I-D.ietf-plants-merkle-tree-certs
   uses the following structure:

~~~
struct {
    uint64 start;
    uint64 end;
    HashValue inclusion_proof<0..2^16-1>;
    MTCSignature signatures<0..2^16-1>;
} MTCProof;
~~~

   Note that it contains start and end values which indicate
   the corresponding parameters of the chosen subtree.  To request the
   required landmark, the client simply combines the URL as follows:

   LandmarkDistributionPoint?st=start?ed=end

   This allows the verifier to request the required landmark so the
   inclusion proof can be verified.

   The verifier needs to trust the issuer as per RFC 5280.


### Format of Landmark

The format of the landmark is defined in section 6.3.3
of I-D.ietf-plants-merkle-tree-certs

As mentioned above, the verifier may need to request the landmark if it
is not readily available.

This draft proposes an extension to the landmark format specified in section
6.3.3 of I-D.ietf-plants-merkle-tree-certs which defines a mechanism for
publishing active landmarks.

The current landmark format describes the tree sizes associated for each
landmark.  However, it does not provide a mechanism for establishing a
cryptographic relationship between a previously published landmark and a
more recent landmark.  This document defines this mechanism as a Landmark
subtree consistency Proof.  It includes carrying the necessary hashes so
that there is a subtree consistency proof from one landmark to the next.
The calculation of the subtree consistency proof from one landmark to the
next can occur when a new landmark is published.  See section
4.4 of I-D.ietf-plants-merkle-tree-certs for information on subtree
consistency proofs.

This will allow for periodic and incremental updates for clients that need to
request information from the LDP server.

#### Landmark subtree consistency proof

A verifier requesting updated landmarks may require a lot of new landmarks.
Requiring the verifier to retrieve and validate every intermediate
landmark would increase both network traffic and signature
verification costs.

To address this problem, this document defines a
LandmarkSubtreeProof object.  A LandmarkSubtreeProof provides cryptographic
evidence that a source landmark identified by one tree size is incorporated
into a target landmark identified by a larger tree size.

The LandmarkSubtreeProof does not modify the landmark publication
format defined in Section 6.3.3.  Instead, it is published as a
separate resource by the Landmark Distribution Point Server
(LDP Server).

The LandmarkSubtreeProof structure is defined as follows:

~~~
struct {
    uint64 source_tree_size;
    uint64 target_tree_size;

    HashValue consistency_proof<0..2^16-1>;
} LandmarkSubtreeProof;
~~~

Where:

source_tree_size (similar to start in MTCProof):
   The tree size corresponding to the source landmark.

target_tree_size (similar to end in MTCProof):
   The tree size corresponding to the target landmark.

consistency_proof:
   A proof demonstrating that the source landmark tree is a
   subtree of the target landmark tree.

The consistency_proof SHALL be constructed so that successful
verification demonstrates that all entries represented by the
source landmark are included in the target landmark and retain
their original ordering and contents.

A LandmarkProof MAY be generated when a new landmark is
published and MAY be retained by the Landmark Distribution
Point for subsequent retrieval by the verifier as needed.

### Landmark Subtree Proof Retrieval

A verifier validating an MTCProof obtains the corresponding
subtree information from the certificate and retrieves the
associated landmark file as described in Section 6.3.3.

If the verifier possesses a trusted landmark whose tree size is
greater than the retrieved landmark's tree size, the verifier
MAY obtain a set of LandmarkSubtreeProofSet connecting the two
landmarks.

#### Landmark Subtree Proof Set

A LandmarkSubtreeProofSet contains an ordered sequence of LandmarkSubtreeProof values. The first proof SHALL be verified against a trusted landmark root. Each subsequent proof SHALL be verified against the landmark root reconstructed from the preceding proof. Successful verification of all contained proofs establishes a cryptographic path from the trusted landmark to the target landmark.

~~~
struct {
    LandmarkSubtreeProof proofSet<0..2^16-1>;
} LandmarkSubtreeProofSet;
~~~

One possible retrieval mechanism is:

~~~
LandmarkDistributionPoint?
    source=<source_tree_size>&
    target=<target_tree_size>
~~~

TODO:  Agree on the URI format

The Landmark Distribution Point Server SHALL return a
LandmarkSubtreeProofSet capable of demonstrating that the source landmark is
incorporated into the target landmark.

### Validation Procedure

A verifier SHALL perform the following steps:

1.  Extract the `start` and `end` values from the MTCProof.

2.  Retrieve the landmark file corresponding to the authenticated
    subtree by contacting the LDP server (or retrieving it
    from a local cache).

3.  Obtain a trusted target landmark if one is not already
    cached. For example, a likely candidate would be the latest
    landmark referenced by the Landmark File.

4.  Verify the signature(s) associated with the trusted target
    landmark.  If signature verification fails, the verifier MUST
    reject the certificate.

6.  If the source subtree landmark and trusted target landmark differ,
    retrieve a LandmarkSubtreeProofSet that establishes a
    sequence of authenticated subtree transitions between the
    source landmark and the trusted target landmark.

7.  Verify each LandmarkSubtreeProof contained in the
    LandmarkSubtreeProofSet in the order in which it appears.
    The first proof SHALL be verified against the source
    landmark. Each subsequent proof SHALL be verified against
    the landmark root reconstructed from the preceding proof.

8.  Successful verification of the complete
    LandmarkSubtreeProofSet SHALL establish that the source
    landmark tree is a cryptographic prefix of the trusted
    target landmark tree.

9.  Use the validated source landmark to verify the Inclusion
    Proof contained within the MTCProof.

10.  Accept the certificate if all verification steps succeed.

Successful completion of this procedure establishes that the
certificate entry is included in the authenticated subtree
identified by the source landmark and that the source landmark
is cryptographically bound via the verified LandmarkSubtreeProofSet
to the trusted target landmark.

### Efficiency Considerations

The purpose of LandmarkSubtreeProofs is to reduce the number of
landmarks and signatures that must be processed by a verifier.

Without LandmarkSubtreeProofs, a verifier may be required to retrieve
multiple intermediate landmarks and validate the signatures
associated with each landmark before reaching a currently
trusted landmark.

With LandmarkProofs, a verifier requires only:

* the source landmark;

* the trusted target landmark; and

* a LandmarkSubtreeProofSet connecting the corresponding tree sizes.

As a result, the number of signature verification operations is
independent of the number of intermediate landmarks published
between the source and target landmarks.

This property is particularly beneficial when signatures are
generated using computationally expensive algorithms,
including post-quantum signature algorithms.

### Skip links for efficiency

TODO:  Generating the consistency proof at the LDP server introduces an O(N^2) problem.  For efficiency, we likely want to cache landmark proofs as they are generated between each landmark.  For example 1->2, 2->3, 3->4 but also 1->3, 1-4, 2-4.  Thus O(n^2).  A better approach is to use a skip link which only generates O(Log(num_landmarks)) for each landmark.  For example, a system that issued a landmark every hour for 10 years would have 87,600 landmarks.  When landmark 87,601 is created, only 17 landmark proofs will need to be created.  It would also reduce the LandmarkSubtreeProofSet from O(num_landmarks) to O(Log(num_landmarks), greatly reducing bandwidth requirements!

### More items to be discussed:
- When a CA issues an MTC certificate, it will decide where the landmark will be published.  It needs to provide the LDP service.
- Current format uses start and end values from the inclusion proof.  This is nice because no other extension is needed in the EE certs
- Landmarks should be available in a predictable way.  The above format should meet this requirement.
- Do Landmark's contain a signature, or is it just the MTH and we use the cumulative landmarks along with the inclusion proof?
   - A:  No, there is one trusted target that contains a signature.  That trusted target should be cached so that the full PQ signatures doesn't need to be continually downloaded.  This is where MTC gets its efficiency.
- Is there a repository of test landmark certificates that we can use to test this mechanism?
   - A:  Seems like a good hackathon project!


### Landmark Distribution server
As mentioned above, the landmarks can be fetched dynamically as needed by
combining the start and end values from the MTCProof.  The LDP server fulfilling
these requests will need to parse the start and end values, aggregate the
require landmark subtrees together, and send the responce back to the client.
The responce format will be:

TODO:  DEFINE responce format


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

For the transparency log to support anomaly detection and post-incident forensics in
code signing deployments, the log MUST record the following information per batch: the
signing algorithm used to produce the batch tree head signature, the timestamp of batch
creation and the issuing CA identity.  Per certificate entry, the log MUST record the
subject identity, the subject public key algorithm, key usage extension values and the
certificate validity period.

Per-certificate algorithm metadata is required for post-quantum migration auditing.  An
organization asserting that its code signing infrastructure issued only post-quantum
certificates from a given date must be able to demonstrate this from the log record,
with cryptographic verifiability that an audit database alone cannot provide.

The following structures define the information model for a code signing log entry.
Two-level recording is used: one record per batch captures the batch-level signing
metadata, and one record per certificate captures the subject-level metadata needed
for monitor evaluation and forensic queries.

~~~
struct CertMetadata {
    opaque subject_identity<0..2^16-1>;
    PublicKeyAlgorithm subject_key_algorithm;
    uint16 key_usage_flags;
    uint64 not_before;
    uint64 not_after;
    uint64 leaf_index;
}

struct CodeSigningLogEntry {
    uint64 batch_id;
    uint64 timestamp;
    SignatureAlgorithm batch_signing_algorithm;
    HashValue batch_tree_head;
    opaque issuing_ca_identity<0..2^16-1>;
    CertMetadata cert_entries<0..2^32-1>;
}
~~~

A signing receipt is the artifact-embedded object that binds a signed binary, container
image or firmware update to a specific log entry.  The receipt travels inside the
artifact's signature container alongside the standalone MTC.  A verifier extracts the
receipt, verifies the batch_root_signature against the locally-held CA trust anchor,
and then verifies the inclusion_proof to confirm that the signing certificate is a leaf
in the identified batch.

~~~
struct SigningReceipt {
    uint64 batch_id;
    uint64 leaf_index;
    HashValue inclusion_proof<0..2^16-1>;
    MTCSignature batch_root_signature;
    uint64 log_commit_timestamp;
    opaque log_operator_id<0..2^16-1>;
}
~~~

When a CA transitions its batch signing from one algorithm class to another, it MUST
publish an AlgorithmTransitionEvent to the transparency log before the first batch
signed under the new algorithm is distributed.  The ca_assertion_signature field is
produced by the CA over the remaining fields of the structure, using the signing key
corresponding to the new_batch_algorithm, providing cryptographic proof that the CA
holding the new key has authorized the transition record.

~~~
struct AlgorithmTransitionEvent {
    uint64 effective_batch_id;
    uint64 timestamp;
    SignatureAlgorithm previous_batch_algorithm;
    SignatureAlgorithm new_batch_algorithm;
    opaque ca_identity<0..2^16-1>;
    MTCSignature ca_assertion_signature;
}
~~~

### Independent Monitor

The transparency log for private PKI code signing MUST be operated independently from
the issuing CA.  A log under the administrative control of the CA operator does not
provide an independent check against the threats described in this section.

An independent monitor consuming the log SHOULD maintain an authoritative register of
entities authorized to hold signing certificates and the algorithm classes they are
authorized to use.  The monitor SHOULD alert on: issuance of a signing certificate to
an entity absent from the authorization register; issuance of a classical algorithm
signing certificate to an entity recorded as having completed migration to post-quantum
algorithms; and any unexplained reduction in post-quantum algorithm usage across
successive batches.

The MonitorAlert structure defines the information model for an alert raised by the
independent monitor.  The evidence_log_reference field carries a reference to the
specific CodeSigningLogEntry or AlgorithmTransitionEvent that triggered the alert,
allowing the recipient to independently verify the raw log data.

~~~
enum AlertType {
    UNAUTHORIZED_ISSUANCE,
    ALGORITHM_DOWNGRADE,
    MIGRATION_REGRESSION,
    FROZEN_DEVICE_ANOMALY
}

struct MonitorAlert {
    AlertType alert_type;
    opaque subject_identity<0..2^16-1>;
    uint64 batch_id;
    uint64 leaf_index;
    uint64 detection_timestamp;
    opaque evidence_log_reference<0..2^16-1>;
}
~~~

### Archival Obligations

Signed artifacts may require verification throughout their operational lifetime, which
in enterprise deployments can span years.  A CA issuing signing certificates MUST retain
accessible archives of all published batch tree heads for a period not less than the
maximum validity period of any certificate in the corresponding batch.  These archives
MUST remain accessible following the decommissioning of the issuing CA and MUST NOT
share infrastructure with the live issuing CA.


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

An entity that has completed migration to post-quantum algorithms should no longer
receive classical algorithm certificates.  During the hybrid transition period,
however, a CA operating both issuance paths may issue a classical certificate to such
an entity through misconfiguration, policy error or deliberate action.  A classical
certificate issued to an entity that accepts only post-quantum certificates can be
used to intercept communications from any relying party that retains classical
certificate trust.

A transparency log with an independent monitor maintaining an authoritative migration
status register enables detection of this event.  The monitor can identify any
classical certificate issuance to an entity recorded as having completed migration
and raise an alert before the certificate is deployed.

The MigrationStatusEntry structure defines the information model for a single entry
in the migration status register.  The status field records the current migration
state of the subject.  The status_effective_date field records the date from which
the recorded status applies, enabling the monitor to correctly classify certificate
issuances that predate a status change.  The policy_reference field carries an
opaque reference to the organizational policy or administrative record that authorized
the recorded status, providing an audit trail for register entries.

~~~
enum MigrationStatus {
    CLASSICAL_ONLY,
    HYBRID,
    PQ_ONLY,
    FROZEN
}

struct MigrationStatusEntry {
    opaque subject_identity<0..2^16-1>;
    MigrationStatus status;
    uint64 status_effective_date;
    opaque policy_reference<0..2^16-1>;
}
~~~

### Frozen Devices

Certain devices in private PKI environments cannot receive updates that would add
post-quantum algorithm support.  Regulatory re-approval requirements, sealed hardware
and immovable service constraints mean that some endpoints will continue to use
classical algorithm certificates for the duration of their service lives, regardless
of the broader migration status of the PKI.

These devices need not implement MTC.  The transparency log supports a monitoring
pattern for frozen device populations in which the CA records classical certificate
issuances for frozen device identifiers and an independent monitor watches those
identifiers for anomalous activity.  The monitor can alert if a classical certificate
is issued for a frozen device identifier by an unexpected CA or with unexpected
attributes.  The monitoring operates independently of the device and provides detection
capability without requiring any modification to device firmware or software.

A FrozenDeviceRecord is a signed assertion by the PKI operator that a specific device
identity is designated as a frozen endpoint.  The record identifies the single CA
authorized to issue classical certificates for the device and the specific algorithm
permitted for those certificates.  The monitor MUST reject any classical certificate
issuance for a frozen device identity that does not match the authorized_issuer_ca_identity
and permitted_key_algorithm fields of the corresponding FrozenDeviceRecord.  The
operator_signature field is produced by the PKI operator over the remaining fields of
the structure, using a key whose public counterpart is held in the monitor's trust
configuration.

~~~
struct FrozenDeviceRecord {
    opaque device_identity<0..2^16-1>;
    opaque authorized_issuer_ca_identity<0..2^16-1>;
    PublicKeyAlgorithm permitted_key_algorithm;
    uint64 record_effective_date;
    uint64 record_expiry_date;
    MTCSignature operator_signature;
}
~~~

### Algorithm Metadata Requirements

For the transparency log to support the use cases described in this section, the log
MUST record the signing algorithm used to produce each batch tree head signature and
the subject public key algorithm for each certificate in each batch.  Per-certificate
algorithm metadata is required because a CA operating during the hybrid transition
period may issue both classical and post-quantum certificates within the same batch.

A CA transitioning between algorithm classes in batch signing MUST record each
transition as a distinct log event with a timestamp.  These records constitute the
verifiable migration timeline that regulatory compliance requirements may demand.

The AlgorithmTransitionEvent structure defined in Section 3.3 is reused here for
recording batch signing algorithm transitions in the PQC migration context.  For
migration auditing purposes, a monitor querying the log for AlgorithmTransitionEvent
entries can reconstruct the complete algorithm transition history for any CA, with
each transition cryptographically bound to the batch at which it took effect.

In addition to batch-level transitions, the log entry for each certificate MUST
carry the subject public key algorithm, as defined in the CertMetadata structure
in Section 3.3.  The monitor evaluates per-certificate algorithm metadata against
the MigrationStatusEntry for each subject to detect unauthorized classical issuance
during the transition period.

### Migration Staging

A private PKI operator deploying MTC during the post-quantum transition period should
proceed through distinct stages.  In the first stage, MTC infrastructure is deployed
with classical batch signing.  The transparency log is operational and all certificate
issuances are recorded, establishing the baseline against which migration progress is
measured.  In the second stage, batch tree head signing transitions to hybrid signatures
incorporating both classical and post-quantum algorithms.  Certificate-level algorithm
migration proceeds at a pace determined by endpoint readiness.  In the third stage,
post-quantum-only batch signing is adopted and the transparency log records this
transition with a timestamp that constitutes the verifiable PQC migration completion
date for the batch signing infrastructure.  In the fourth stage, classical algorithm
certificate issuance is discontinued except for designated frozen device populations,
and the log provides ongoing monitoring capability for those populations.

The duration of each stage depends on the specific PKI deployment, the endpoint
population capabilities and applicable regulatory requirements.


## Constrained Device Certificate Validation

Private PKI deployments include endpoint populations with constraints on available
memory, processing capacity and network access.  Access control readers validating
employee identity credentials, sensors on isolated operational technology networks
and embedded controllers in long-lived infrastructure may need to validate
certificates issued over an extended time window, potentially spanning years, without
the ability to maintain a continuously updated landmark cache or retrieve landmarks
on demand.

This use case is distinct from the landmark distribution use case in Section 3.1,
which addresses endpoints with network connectivity capable of fetching landmarks as
needed.  This section addresses endpoints for which neither real-time landmark
retrieval nor continuous landmark cache maintenance can be assumed.

### The Landmark Accumulation Problem

In a traditional X.509 deployment, a constrained verifier typically holds one or more
trust anchor certificates and retrieves revocation data periodically.  Each CRL
supersedes its predecessor and the verifier need not retain prior revocation data.
Storage requirements are bounded and predictable.

Under MTC, landmark-relative certificate validation requires the verifier to hold the
landmark corresponding to the batch in which the subject certificate was issued.  A
newer landmark does not supersede an older one for the purpose of validating
certificates issued against an older batch.  A device that must validate certificates
issued over a ten-year window must retain every landmark published during that period.
The storage requirement grows linearly with the landmark publication frequency and the
length of the validation window.

The storage requirement can be bounded as follows.  Let W be the validation window in
days, F be the landmark publication frequency in days per landmark and S be the size
of a single landmark in bytes.  The minimum storage required for landmark retention is:

~~~
  Storage = ceiling(W / F) * S
~~~

As an example, a device validating certificates with a ten-year validity window against
daily-published landmarks of 512 bytes each requires approximately 1.83 MB of dedicated
landmark storage.  PKI operators SHOULD calculate this value when evaluating MTC
deployment for constrained device populations and SHOULD select landmark publication
frequency with reference to the storage capacity of the most constrained device in the
target population.

### Landmark Rebasing

Where the calculated storage requirement exceeds the available capacity of constrained
devices, a rebasing mechanism may reduce the number of landmarks a device must retain.
A rebase operation produces a new landmark that cryptographically subsumes a range of
prior landmarks, allowing the device to replace that range with a single object.

For a rebase to be valid, the device must be able to verify that the rebased landmark
correctly represents all certificates included in the prior landmarks it replaces.  A
rebase accompanied only by a new tree head and a CA signature does not provide this
assurance.  The rebased landmark MUST be accompanied by a proof demonstrating that the
prior landmark trees are subtrees of the rebased tree.  The LandmarkSubtreeProof
mechanism defined in Section 3.1.4 of this document provides a suitable proof structure
for this purpose.

A device accepting a rebased landmark MUST verify the accompanying subtree consistency
proof before discarding any landmark that the rebase replaces.  A device that accepts
a rebased landmark without verification is vulnerable to a history replacement attack
in which an adversary substitutes a fraudulent tree head, potentially causing the
device to reject valid certificates or accept fraudulent ones.

### Re-anchoring After Extended Offline Periods

A device that has been without network access for an extended period accumulates a
deficit of landmarks issued during its offline interval.  Upon reconnecting, the
device must obtain those landmarks before it can validate certificates issued during
the offline period.

A device re-anchoring after an extended offline interval SHOULD use the
LandmarkSubtreeProofSet mechanism defined in Section 3.1.4 to obtain a compact proof
connecting its most recent trusted landmark to the current landmark, rather than
retrieving each intermediate landmark individually.  This minimizes both the bandwidth
required for re-anchoring and the number of signature verifications the device must
perform.  For deployments using post-quantum signature algorithms, the reduction in
signature verification operations is particularly significant given the higher
per-verification cost of those algorithms.

A device re-anchoring after an offline interval is exposed to rollback attacks in which
an adversary presents an outdated landmark as the current one.  Devices SHOULD implement
a monotonicity check on landmark tree sizes, rejecting any proposed current landmark
with a tree size smaller than that of the most recently validated trusted landmark.

The monotonicity check depends on the device retaining its most recently validated
landmark state across power cycles and resets.  The LandmarkState structure defines
the minimum persistent state a device must maintain to support this check.  The
max_observed_tree_size field records the largest tree size the device has successfully
validated.  The last_trusted_tree_head field records the hash of the corresponding
landmark, enabling the device to detect inconsistency if a claimed current landmark
has a tree size equal to max_observed_tree_size but a different tree head value.
This state MUST be stored in integrity-protected persistent storage.  Devices without
such storage cannot provide rollback resistance and SHOULD obtain landmarks exclusively
through authenticated channels that provide freshness guarantees.

~~~
struct LandmarkState {
    uint64 max_observed_tree_size;
    uint64 last_update_timestamp;
    HashValue last_trusted_tree_head;
}
~~~

### Guidance for PKI Operators

PKI operators deploying MTC for constrained device populations SHOULD publish landmark
storage requirements as part of deployment documentation.  This documentation SHOULD
include the landmark publication frequency, the expected certificate validity period for
the target population, the per-landmark storage size and the calculated storage bound
using the formula in Section 3.4.2.

Operators SHOULD also document the procedure for landmark rebasing if that capability
is provided, including the expected rebase frequency and the verification procedure
devices are expected to follow.

Where a single PKI serves both constrained and non-constrained device populations,
operators SHOULD consider whether separate landmark publication schedules are warranted,
with a lower-frequency schedule for constrained populations.  The LDP infrastructure
defined in Section 3.1 may continue to serve non-constrained populations, while
constrained populations receive pre-provisioned landmark packages through an out-of-band
distribution mechanism suited to their connectivity characteristics.

A LandmarkPackage is the container format for a pre-provisioned set of landmarks
distributed to constrained devices through out-of-band channels.  The package carries
a contiguous range of landmarks from source_tree_size to target_tree_size, together
with a LandmarkSubtreeProof demonstrating that the source landmark is a cryptographic
prefix of the target landmark.  The package_signature field is produced by the CA
over the remaining fields of the structure.  A device receiving a LandmarkPackage
MUST verify the package_signature before accepting any landmark contained in the
package, and MUST verify the consistency_proof before updating its LandmarkState.
The source_tree_size in the package MUST be greater than or equal to the
max_observed_tree_size recorded in the device's current LandmarkState.

~~~
struct LandmarkPackage {
    uint64 package_version;
    uint64 creation_timestamp;
    uint64 source_tree_size;
    uint64 target_tree_size;
    Landmark landmarks<0..2^16-1>;
    LandmarkSubtreeProof consistency_proof;
    MTCSignature package_signature;
}
~~~


# Security Considerations

TODO Security


# IANA Considerations

This document requests a new id-pe-ldpBaseURIs extension for use with X.509 certificates
in the "SMI Security for PKIX Certificate Extension" registry (1.3.6.1.5.5.7.1).

--- back

# Acknowledgments
Thanks to David Benjamin, Bas Westerbaan, Mike Ounsworth, Tirumaleswar Reddy, Rich Salz and Kris Kwiatkowski for their feedback and review of this specification.
