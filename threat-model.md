# Threat Model — LLM Inference Security Gateway

## Scope

Threat model covers the inference pipeline from API gateway ingress to model response delivery. Excludes: VPC/network layer controls, Cloud IAM, model training data security.

## What We're Protecting

| Asset | Value | If Compromised |
|---|---|---|
| System prompt / configuration | Confidentiality | Attacker learns exact detection boundaries, crafts targeted bypasses |
| User PII in context window | Confidentiality | Regulatory violation (GDPR, PCI-DSS), reputational damage |
| Model behavior | Integrity | Model acts against its intended role (answers questions it shouldn't, takes unintended actions) |
| Inference endpoint availability | Availability | Service disruption, fail-closed triggers downstream |
| RAG document store | Integrity | Poisoned documents cause indirect injection in all downstream queries |

---

## Threat Actors

**T1: External Attacker (no system knowledge)**  
Knows the API exists. Tries standard prompt injection payloads from public databases (OWASP LLM Top 10, PromptBench, HackAPrompt).  
Capability: Low to medium. Coverage: Pattern matching catches most known payloads.

**T2: Informed Attacker (knows pattern set)**  
Has enumerated the detection patterns through repeated probing (observing 422 vs 200 responses). Crafts payloads specifically designed to evade known patterns.  
Capability: High. Coverage: Heuristic layer provides partial coverage; output filter catches exfiltration attempts; rate limiting (not in this layer) should limit enumeration.

**T3: RAG Document Store Attacker**  
Can write documents to the document store (via compromised service account, misconfigured write permissions, or injection into an indexing pipeline). Embeds malicious instructions in documents that appear legitimate.  
Capability: Medium, requires write access to document store. Coverage: `analyze_context()` — the primary control for this threat.

**T4: Insider Threat**  
Authorized user attempting to misuse the system beyond their intended scope. Knows system prompt structure.  
Capability: High for targeted attacks. Coverage: Audit logging is the primary control; detection adds a detection signal but determined insider can craft evasion.

---

## Attack Flows

### A1: Direct Prompt Injection (T1, T2)

```
Attacker → POST /detect or /safe-inference
         → Malicious prompt in request body
         → Detector runs pattern matching + heuristics
         → [Caught] 422 returned, logged as security event
         → [Missed - novel attack] Prompt reaches model
           → Output filter catches PII in response
           → [Still missed] Model responds with exfiltrated data
```

Controls: Pattern matching (Layer 2), heuristics (Layer 2), output filter (Layer 3).  
Residual risk: Novel attacks that evade all patterns and don't trigger heuristics, and where model response contains no detectable PII.

### A2: Indirect Injection via RAG Poisoning (T3)

```
Attacker → Writes poisoned document to document store
         → Document indexed into vector DB
         → Legitimate user query → vector search returns poisoned chunk
         → [Without this system] Chunk inserted into prompt, injection executes
         → [With this system] analyze_context() scans chunks
           → Poisoned chunk identified, dropped from context
           → Query proceeds with reduced context
```

Controls: `analyze_context()` — this is the primary and only control for this attack vector.  
Residual risk: Poisoned document that embeds injection in a way that evades all detection patterns.  
Note: Document store write access is a security boundary — who can write documents must be restricted. This system detects poisoning but doesn't prevent it.

### A3: Fail-Closed Exploitation (T2)

```
Attacker → Triggers high traffic to crash/OOM the detector
         → Detector health fails
         → [Fail-open] Requests continue to model unscreened ← we prevent this
         → [Fail-closed] All requests blocked until recovery
```

Controls: Fail-closed behavior. Detection of targeted DoS against detector is outside scope of this component (should be handled at WAF/API gateway layer).

### A4: Response Exfiltration via Model Memory (T1, T2)

```
Attacker → Sends legitimate-looking prompt
         → Model response contains credential/PII from training data or context
         → [Without this system] Exfiltrated data reaches attacker
         → [With this system] Output filter redacts before delivery
```

Controls: Output filter PII redaction (7 pattern types including cloud credentials).

---

## What This System Doesn't Protect Against

**Not in scope by design:**
- Attacks that require compromising the model itself (adversarial training, model poisoning)
- Network-level attacks (DDoS, MitM) — handled at infrastructure layer
- Authentication bypass — handled at API gateway
- Credential theft from the application server

**Known gaps:**
- Novel zero-day injection patterns with no structural anomalies
- Multilingual injection in non-Latin scripts (partial coverage via homoglyph normalization)
- Semantic-level attacks (grammatically valid sentences that instruct without pattern triggers)
- Adaptive adversaries who can probe the pattern boundary at low volume

**Mitigations for known gaps:**
- Output filter as last-resort catch
- Least-privilege model permissions (model should have minimal data access)
- Async embedding pipeline for deeper analysis (not implemented in this version)
- Rate limiting + jitter on 422 responses to slow pattern enumeration
