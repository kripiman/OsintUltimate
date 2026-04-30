# 兵器補遺 2026 — Plugin Gaps for BB Pro

> 文言ultra. 補arsenal之缺. 2026 BB職業級.

## 0. 現狀 (Status)

106 plugin .rs. Tier 1-3 完成. 然 modern BB 2026 → 缺 LLM/AI sec ✅, modern JS recon ✅, mobile (5/7 ✅), web3, supply-chain深度 ✅, AD後階. 補之.

---

## 1. 缺口分類 (Gap Matrix)

| 類 | 現有 | 缺 | 優先 |
|---|---|---|---|
| OSINT modern | Subfinder/Amass/Uncover/AlterX/CertStream | BBOT, Chaos, theHarvester, SpiderFoot, holehe, Photon, ShodanX, Censys-CLI, FOFA-CLI, Cero, dnsgen, gotator, shuffledns, asnmap, mapcidr, tlsx, cdncheck, smap | P0 |
| JS/Front | JSluice | LinkFinder ✅, SecretFinder ✅, getJS, subjs ✅, sourcemapper ✅, retire.js ✅, JSFScan | P0 |
| API modern | InQL ✅, GraphQL-Cop ✅, GraphW00f ✅, Crackql ✅, schemathesis ✅ | restler-fuzzer, Mantra, postman2burp, autoswagger | P0 |
| WebSocket/gRPC/SOAP | nil | wsrepl, grpcurl, grpcox, wsdler | P1 |
| Web exploit 2026 | sqlmap/dalfox/commix/tplmap/ssrf-king/openredirex/smuggler/jwt/nomore403 | XSStrike, SSRFmap, h2csmuggler, race-the-web, param-miner-bridge, ysoserial(.net), GadgetProbe, XXEinjector, lfimap, liffy, ssimap | P0 |
| AI/LLM sec | nil | Garak, PyRIT, promptmap, Vigil, Rebuff, Promptfoo, LLMFuzzer, modelscan, PromptInject | **P0** |
| Mobile | MobSF/apktool/jadx/drozer/APKLeaks (5/7) | frida-automate, objection, mariana-trench | P0 |
| Web3 | nil | Slither, Mythril, Echidna, Manticore, Aderyn | P2 |
| Cloud深度 | Pacu/Prowler/CloudFox/CloudEnum/CloudBrute/KubeBench | ScoutSuite, cloudsplaining, S3Scanner, GCPBucketBrute, cloudgrappler, endgame, Stratus-Red-Team, Leonidas, peirates, kubehound, kubeletctl, kdigger | P0 |
| Supply chain | Trivy/OSV/Checkov/Kubescape, Syft ✅, Grype ✅, Cosign ✅ | dive, dependency-check, semgrep | P0 |
| Net scan 2026 | Naabu/Nmap/Rustscan | masscan, zmap, smap, sshamble, kerbrute, ldapsearch-ad | P1 |
| AD後階 | Bloodhound/Impacket/NetExec/Responder/Coercer/Petitpotam/Certipy | Snaffler, ADRecon, NoPac-rs, Rubeus-port, SauronEye, kubehound-ad | P1 |
| Wireless | empty mod | aircrack-ng, hcxtools, wifite, kismet, bettercap | P2 |
| Detection evasion | empty mod | donut, sleepmask, obfuscator-llvm-wrap, fluxguard, AMSI/EDR-bypass-stub | P1 |
| OSINT 人 | nil | sherlock, holehe, pwndb, maigret, OSRFramework | P2 |
| Wordlist/aux | nil | SecLists-auto, cewl, oneforall | P1 |
| Reporting | bug_bounty.rs | Dradis-export, Pwndoc-export, DefectDojo-API | P2 |

---

## 2. P0 必加 (Critical 2026)

### 2.1 AI/LLM 紅隊 (新興最熱)

```
Garak       → LLM vuln scanner ✅
PyRIT       → MS Red Team automation framework ✅
promptmap   → prompt injection mapping ✅
Vigil       → LLM input/output filter audit
Rebuff      → prompt injection detection
Promptfoo   → eval harness, regression for LLM apps ✅
LLMFuzzer   → black-box LLM fuzzer ✅
modelscan   → ML model file (pkl/h5/onnx) malware scan
PromptInject→ classic injection corpus ✅
```

→ 新plugin path: `src/plugins/exploitation/ai_llm/`

### 2.2 OSINT 現代

```
BBOT        → recon framework, modular, 2024+ dominant
Chaos       → projectdiscovery subdomain DB API
theHarvester→ email/host/employee OSINT
SpiderFoot  → automated OSINT graph
asnmap      → ASN → CIDR
mapcidr     → CIDR ops
tlsx        → TLS cert recon mass
cdncheck    → CDN bypass aid
shuffledns  → mass DNS resolver
dnsgen/gotator → permutation gen (vs AlterX互補)
smap        → shodan-backed port scan (zero-traffic)
ShodanX/Censys-CLI/FOFA-CLI → motor wrappers
```

→ paths: `reconnaissance/osint/{bbot.rs,chaos.rs,theharvester.rs,spiderfoot.rs}`, `reconnaissance/active/{shuffledns.rs,asnmap.rs,tlsx.rs,cdncheck.rs}`

### 2.3 JS Deep Recon

```
LinkFinder    → endpoint regex from JS ✅
SecretFinder  → API keys/secret patterns ✅
getJS / subjs → mass JS URL extract ✅
sourcemapper  → restore source from .js.map ✅
retire.js     → vuln JS lib detect (CVE map) ✅
```

→ `reconnaissance/passive/js/{linkfinder.rs,secretfinder.rs,subjs.rs,sourcemapper.rs,retire.rs}`

### 2.4 API/Schema Fuzz

```
schemathesis  → OpenAPI/GraphQL property-based fuzz ✅
restler-fuzzer→ MS stateful REST fuzzer
GraphW00f     → GraphQL engine fingerprint (pre-attack) ✅
Crackql       → GraphQL brute/DoS ✅
Mantra        → JS API key sweep
autoswagger   → Swagger auth bypass auto
```

→ `enumeration/web/api/{schemathesis.rs,restler.rs,graphw00f.rs,crackql.rs,autoswagger.rs}`

### 2.5 Web Exploit 補

```
XSStrike      → DOM/reflected XSS (vs Dalfox補)
SSRFmap       → param-aware SSRF (vs ssrf-king blind補)
h2csmuggler   → HTTP/2 cleartext smuggle (Smuggler不cover)
ysoserial(.net)+GadgetProbe → Java/.NET deser
XXEinjector   → blind XXE OOB (Interactsh chain)
lfimap/liffy  → LFI auto
ssimap        → SSI inject
race-the-web  → race condition (Turbo-Intruder類)
```

→ `exploitation/web/{xsstrike.rs,ssrfmap.rs,h2csmuggler.rs,ysoserial.rs,xxeinjector.rs,lfimap.rs,race.rs}`

### 2.6 Mobile (現zero)

```
MobSF        → static+dynamic Android/iOS ✅
apktool/jadx → APK decompile ✅
Frida-auto   → instrumentation harness
objection    → frida wrapper
drozer       → Android attack surface ✅
APKLeaks     → secrets in APK ✅
mariana-trench→ FB taint analysis
```

→ `exploitation/mobile/{mobsf.rs,apktool.rs,jadx.rs,frida.rs,objection.rs,drozer.rs,apkleaks.rs}`

### 2.7 Cloud/K8s 深度

```
ScoutSuite      → multi-cloud audit (vs Prowler補AWS外)
cloudsplaining  → AWS IAM least-priv gap
S3Scanner/GCPBucketBrute → bucket enum
cloudgrappler   → APT TTP detect cloud logs
endgame         → AWS resource share/exposure
Stratus-Red-Team→ TTP simulation cloud
Leonidas        → AWS attack technique catalog
peirates        → k8s pod escape
kubehound       → k8s attack graph (Bloodhound-like)
kubeletctl      → kubelet abuse
kdigger         → k8s context discovery
```

→ `enumeration/cloud/{scoutsuite.rs,cloudsplaining.rs,s3scanner.rs,gcpbucketbrute.rs,stratus.rs}`, `exploitation/cloud/{peirates.rs,kubehound.rs,kubeletctl.rs,kdigger.rs}`

### 2.8 Supply Chain 2026

```
Syft     → SBOM generate
Grype    → vuln from SBOM (faster Trivy互補)
Cosign   → sig verify
dive     → docker layer scan
semgrep  → SAST rules engine
dependency-check → OWASP CVE map
```

→ `compliance/{syft.rs,grype.rs,cosign.rs,dive.rs,semgrep.rs}`

---

## 3. P1 強化 (High value)

```
Net 2026: masscan, zmap, smap, sshamble, kerbrute, ldapsearch-ad
AD post:  Snaffler, ADRecon, NoPac-rs, Rubeus-port, SauronEye, kubehound-ad
WS/gRPC:  wsrepl, grpcurl, grpcox, wsdler
Evasion:  donut, sleepmask, obfuscator-llvm-wrap, fluxguard, AMSI/EDR-bypass-stub
Wordlist: SecLists-auto, cewl, oneforall
```

---

## 4. P2 補遺 (Niche / Future)

```
Web3:     Slither, Mythril, Echidna, Manticore, Aderyn
Wireless: aircrack-ng, hcxtools, wifite, kismet, bettercap
OSINT人:  sherlock, holehe, pwndb, maigret, OSRFramework
Reports:  Dradis, Pwndoc, DefectDojo-API
```

---

## 5. 編排策略 (Orchestration Hooks)

新chain rules需:

```
JS-found-secret  → SecretFinder → Trufflehog-validate → Interactsh-OOB
GraphQL-detected → GraphW00f → InQL → Crackql → graphql_cop
OpenAPI-spec     → schemathesis(black) → restler(stateful) → Mantra
APK-target       → APKLeaks → MobSF-static → Frida-dyn → objection
LLM-endpoint     → Garak-probe → promptmap → Vigil-eval
K8s-token        → kdigger-ctx → peirates-escape → kubehound-graph
Java-deser-hint  → GadgetProbe → ysoserial → exploit
S3/GCS-found     → S3Scanner → endgame → cloudsplaining-IAM
```

→ extend `Orchestrator` chain table in `orchestrator.rs`. AI router weights → LLM/cloud/mobile findings 高分 (2026 bounty top payout).

---

## 6. 實作順序 (Build Order)

```
Sprint 1 (P0 critical):   AI/LLM(3 restantes: Vigil, Rebuff, modelscan) + Mobile(2 restantes: frida, objection) + JS-deep(0) → 5 plugin
Sprint 2 (P0 補):
  OSINT-modern(13) + API-fuzz(3 restantes: restler, mantra, autoswagger) + Web-exploit(7) → 23 plugin
Sprint 3 (P0 cloud):
  Cloud深度(11) + Supply-chain(3 restantes: dive, semgrep, dependency-check) → 14 plugin
Sprint 4 (P1):
  Net+AD+Evasion+WS/gRPC+Wordlist → 16 plugin
Sprint 5 (P2):
  Web3+Wireless+OSINT人+Report → 16 plugin
TOTAL → 74 new plugin → arsenal 180
```

---

## 7. 結論 (Conclusion)

現 V14 → BB tradicional 完備. 缺 → AI/LLM(熱), Mobile(高payout), Cloud-深(K8s/IAM), Supply(SBOM/sig), JS-深, API-stateful-fuzz.

✅ **V14.8 SOVEREIGN PIPELINE**: Integrated reactive chains for Mobile (.apk detection), Cloud (K8s/S3 detection), and AI (Endpoint fingerprinting).

加 P0 (42 plugin) → 2026 競爭級.
加 P0+P1 → 業界領先.
加 P0+P1+P2 (74) → 唯一級 (sovereign-grade).

> 兵者，凡七十四. 補之則無雙.
