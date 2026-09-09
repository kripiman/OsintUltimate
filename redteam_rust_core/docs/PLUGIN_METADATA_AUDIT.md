# 📜 Plugin Metadata Audit Report

Este reporte documenta el estado y completitud de los metadatos para todos los plugins registrados.

## Resumen de Hallazgos

- **Total de plugins analizados**: 142
- **Total de Scanners**: 132
- **Total de Discovery Plugins**: 10

## Auditoría Detallada de Scanners

| # | Name | Risk Level | Scan Layer | Category | Cost | Is Destructive | Poc Mode | Capabilities | Mitre Attacks |
|---|---|---|---|---|---|---|---|---|---|
| 1 | WebFuzzer | Medium | Scanning | Enumeration | 5 | false | false | [VulnerabilityScanning] | [] |
| 2 | NmapScanner | Medium | Scanning | Enumeration | 5 | false | true | [VulnerabilityScanning] | ["T1046"] |
| 3 | WhatWebScanner | Medium | Discovery | Enumeration | 5 | false | true | [VulnerabilityScanning] | ["T1592"] |
| 4 | SqlMapScanner | Medium | Scanning | Web/Exploitation | 1 | false | true | [] | [] |
| 5 | HydraScanner | Medium | Exploitation | Exploitation | 5 | false | false | [VulnerabilityScanning] | [] |
| 6 | WapitiScanner | Medium | Exploitation | Exploitation | 5 | false | false | [VulnerabilityScanning] | [] |
| 7 | ZapScanner | Medium | Exploitation | Verification | 5 | false | true | [VulnerabilityScanning] | [] |
| 8 | BurpScanner | Medium | Exploitation | Verification | 5 | false | true | [VulnerabilityScanning] | [] |
| 9 | NucleiScanner | Medium | Scanning | Intelligence | 5 | false | true | [VulnerabilityScanning] | ["T1595", "T1190"] |
| 10 | FfufScanner | Medium | Scanning | Enumeration | 5 | false | true | [WebFuzzing] | ["T1595"] |
| 11 | ArjunScanner | Medium | Scanning | Enumeration | 5 | false | true | [VulnerabilityScanning] | ["T1595"] |
| 12 | RustScanScanner | Medium | Discovery | Enumeration | 5 | false | true | [PortScanning] | ["T1046"] |
| 13 | kerbrute | Medium | Scanning | ActiveDirectory | 2 | false | true | [ActiveDirectory, BruteForce] | ["T1087.002"] |
| 14 | enum4linux-ng | Medium | Scanning | ActiveDirectory | 3 | false | true | [ActiveDirectory, ServiceDiscovery, InformationGathering] | ["T1087", "T1039", "T1135"] |
| 15 | NetExecScanner | Medium | PostExploitation | Exploitation | 5 | false | false | [VulnerabilityScanning, BruteForce] | [] |
| 16 | TrufflehogScanner | Medium | Passive | Reconnaissance | 5 | false | false | [SecretDiscovery] | [] |
| 17 | DalfoxScanner | Medium | Exploitation | Exploitation | 5 | false | true | [VulnerabilityScanning] | ["T1190"] |
| 18 | KatanaScanner | Medium | Scanning | Enumeration | 5 | false | true | [WebFuzzing, ServiceDiscovery] | [] |
| 19 | BloodHoundScanner | Medium | PostExploitation | Lateral Movement | 5 | false | false | [ActiveDirectory] | ["T1087.002", "T1482", "T1069.002"] |
| 20 | ResponderScanner | Medium | PostExploitation | Exploitation | 5 | false | false | [ActiveDirectory] | ["T1557.001"] |
| 21 | SliverAutomator | High | PostExploitation | Exploitation | 10 | false | false | [Evasion, AuthStateMachine] | ["T1570", "T1021.002"] |
| 22 | ImpacketScanner | Medium | PostExploitation | Exploitation | 5 | false | false | [ActiveDirectory] | [] |
| 23 | CertipyScanner | Medium | PostExploitation | Privilege Escalation | 5 | false | false | [VulnerabilityScanning] | [] |
| 24 | PetitPotamScanner | Medium | PostExploitation | Exploitation | 5 | false | false | [VulnerabilityScanning] | [] |
| 25 | SliverScanner | High | PostExploitation | Lateral Movement | 10 | false | false | [VulnerabilityScanning] | ["T1105", "T1071"] |
| 26 | ScoutSuiteScanner | Medium | Scanning | Cloud | 8 | false | true | [] | [] |
| 27 | LigoloScanner | Medium | PostExploitation | Lateral Movement | 5 | false | false | [VulnerabilityScanning] | ["T1090", "T1572"] |
| 28 | PacuScanner | Medium | Scanning | Enumeration | 5 | false | false | [CloudAudit] | [] |
| 29 | CloudEnumScanner | Medium | Passive | Enumeration | 5 | false | false | [CloudAudit] | [] |
| 30 | HttpxScanner | Medium | Discovery | Reconnaissance | 5 | false | false | [VulnerabilityScanning] | [] |
| 31 | NaabuScanner | Medium | Discovery | Reconnaissance | 5 | false | false | [VulnerabilityScanning] | [] |
| 32 | InteractshScanner | Medium | Scanning | Enumeration | 5 | false | false | [VulnerabilityScanning] | [] |
| 33 | HavocScanner | High | PostExploitation | Persistence | 10 | false | false | [VulnerabilityScanning] | ["T1543", "T1053"] |
| 34 | CloudFoxScanner | Medium | Passive | Enumeration | 5 | false | false | [VulnerabilityScanning] | [] |
| 35 | kiterunner | Medium | Discovery | Enumeration | 5 | false | false | [VulnerabilityScanning] | [] |
| 36 | kubescape | Medium | Passive | Compliance | 5 | false | false | [VulnerabilityScanning] | [] |
| 37 | GitleaksScanner | Medium | Scanning | Reconnaissance | 1 | false | true | [] | [] |
| 38 | TsunamiScanner | Medium | Scanning | Enumeration | 1 | false | true | [] | [] |
| 39 | CheckovScanner | Medium | Passive | Compliance | 5 | false | false | [VulnerabilityScanning] | [] |
| 40 | JwtToolScanner | Medium | Exploitation | Exploitation | 5 | false | false | [VulnerabilityScanning] | [] |
| 41 | gowitness | Medium | Discovery | Enumeration | 5 | false | false | [VulnerabilityScanning] | [] |
| 42 | searchsploit | Medium | Discovery | Intelligence | 5 | false | false | [VulnerabilityScanning] | [] |
| 43 | trivy | Medium | Passive | Compliance | 5 | false | false | [VulnerabilityScanning] | [] |
| 44 | feroxbuster | Medium | Scanning | Enumeration | 5 | false | false | [WebFuzzing] | [] |
| 45 | gauplus | Medium | Scanning | General | 5 | false | false | [VulnerabilityScanning] | [] |
| 46 | dnsx | Medium | Discovery | Reconnaissance | 5 | false | true | [VulnerabilityScanning] | ["T1016"] |
| 47 | cloudbrute | Medium | Discovery | Enumeration | 5 | false | false | [VulnerabilityScanning] | [] |
| 48 | nikto | Medium | Scanning | Enumeration | 5 | false | false | [VulnerabilityScanning, WebFuzzing] | [] |
| 49 | wp-scanner | Medium | Scanning | Enumeration | 5 | false | false | [VulnerabilityScanning] | [] |
| 50 | snallygaster | Low | Scanning | Enumeration | 5 | false | false | [SecretDiscovery, VulnerabilityScanning] | [] |
| 51 | WaybackScanner | Safe | Passive | Reconnaissance | 2 | false | false | [HistoricalRecon, OsintDiscovery] | [] |
| 52 | WaymoreScanner | Safe | Passive | Reconnaissance | 4 | false | true | [HistoricalRecon, OsintDiscovery] | ["T1594"] |
| 53 | JaelesScanner | Medium | Scanning | Intelligence | 5 | false | false | [VulnerabilityScanning] | [] |
| 54 | ProwlerScanner | Safe | Passive | Enumeration | 7 | false | false | [CloudAudit, ConfigAudit, IAMAssessment] | [] |
| 55 | KubeBenchScanner | Safe | Passive | Enumeration | 3 | false | false | [InfrastructureAudit, ConfigAudit] | [] |
| 56 | OsvScanner | Safe | Passive | Compliance | 2 | false | false | [SCA, SecurityAuditing] | [] |
| 57 | CRLFuzz | Low | Scanning | Enumeration | 3 | false | false | [VulnerabilityScanning, WebFuzzing] | [] |
| 58 | GfScanner | Safe | Scanning | Enumeration | 1 | false | false | [SecurityAuditing, OsintDiscovery] | [] |
| 59 | CommixScanner | High | Exploitation | Web/Exploitation | 7 | false | true | [VulnerabilityScanning] | ["T1190"] |
| 60 | PrivescHunterScanner | Medium | Scanning | PrivEsc | 1 | false | true | [] | [] |
| 61 | graphql-cop | Safe | Exploitation | Web/API | 2 | false | false | [GraphQL, ApiSecurity] | ["T1595.002", "T1190"] |
| 62 | coercer | Medium | Exploitation | Active Directory | 4 | false | false | [AdCoercion, ActiveDirectory] | ["T1187", "T1557"] |
| 63 | CaidoScanner | Medium | Exploitation | Verification | 4 | false | true | [VulnerabilityScanning, ApiSecurity] | [] |
| 64 | JsluiceScanner | Low | Scanning | Enumeration | 2 | false | true | [VulnerabilityScanning, InformationGathering] | ["T1592", "T1595"] |
| 65 | SubzyScanner | Low | Discovery | Reconnaissance | 2 | false | true | [VulnerabilityScanning, SubdomainEnumeration] | ["T1583.001"] |
| 66 | NoMore403Scanner | Medium | Exploitation | Exploitation | 3 | false | true | [VulnerabilityScanning] | ["T1595.002"] |
| 67 | SmugglerScanner | High | Exploitation | Exploitation | 10 | false | true | [HTTPRequestSmuggling] | ["T1213"] |
| 68 | GreyNoiseScanner | Safe | Passive | Intelligence | 1 | false | true | [InformationGathering] | ["T1592"] |
| 69 | X8Scanner | Medium | Scanning | Enumeration | 4 | false | true | [VulnerabilityScanning] | ["T1595.002"] |
| 70 | InQLScanner | Safe | Scanning | Web/API | 2 | false | true | [GraphQL, ApiSecurity] | ["T1595.002"] |
| 71 | SyftScanner | Low | Scanning | Compliance | 5 | false | false | [VulnerabilityScanning] | ["T1584"] |
| 72 | GrypeScanner | Medium | Scanning | Compliance | 8 | false | false | [VulnerabilityScanning] | ["T1588.006"] |
| 73 | CosignScanner | Medium | Scanning | Compliance | 3 | false | false | [VulnerabilityScanning] | ["T1553"] |
| 74 | PpmapScanner | Medium | Scanning | Web | 2 | false | true | [VulnerabilityScanning, ApiSecurity] | ["T1595.002"] |
| 75 | CorsyScanner | Low | Scanning | Web | 2 | false | true | [VulnerabilityScanning, ApiSecurity] | ["T1595.002"] |
| 76 | WcdScanner | Low | Scanning | Web | 2 | false | true | [VulnerabilityScanning] | ["T1595.002"] |
| 77 | SsrfKingScanner | Medium | Scanning | Exploitation | 8 | false | true | [VulnerabilityScanning] | ["T1134"] |
| 78 | TplmapScanner | High | Exploitation | Web/Exploitation | 6 | false | true | [VulnerabilityScanning] | ["T1190"] |
| 79 | OpenRedirexScanner | Medium | Exploitation | Web/Exploitation | 3 | false | true | [VulnerabilityScanning] | ["T1204"] |
| 80 | LinkFinderScanner | Low | Scanning | Web/Enumeration | 2 | false | false | [VulnerabilityScanning] | ["T1592"] |
| 81 | GraphW00fScanner | Low | Scanning | Enumeration | 3 | false | false | [GraphQL] | ["T1595.002"] |
| 82 | schemathesis | Safe | Scanning | API Security | 3 | false | true | [VulnerabilityScanning] | ["T1595.002"] |
| 83 | crackql | Medium | Scanning | API Security | 2 | false | true | [VulnerabilityScanning] | ["T1110"] |
| 84 | SecretFinderScanner | Medium | Scanning | Web/Enumeration | 3 | false | false | [VulnerabilityScanning] | ["T1552"] |
| 85 | subjs | Safe | Discovery | JS Recon | 1 | false | false | [JsAnalysis] | ["T1595"] |
| 86 | retire | Safe | Scanning | JS Recon | 2 | false | true | [JsAnalysis] | ["T1595"] |
| 87 | sourcemapper | Safe | Scanning | JS Recon | 2 | false | true | [JsAnalysis] | ["T1595"] |
| 88 | UploadStrike | High | Scanning | Exploitation | 1 | false | true | [UploadTesting] | [] |
| 89 | BusinessLogic | Medium | Scanning | Exploitation | 1 | false | true | [IdorDetection, RaceConditionTesting, MassAssignmentTesting] | [] |
| 90 | semgrep | Safe | Scanning | Compliance | 5 | false | true | [SecurityAuditing] | ["T1592"] |
| 91 | oauth_security | Safe | Scanning | Web | 3 | false | true | [ApiSecurity] | ["T1550.001"] |
| 92 | wcvs | Safe | Scanning | Web | 3 | false | true | [ApiSecurity] | ["T1190"] |
| 93 | deserialization | High | Exploitation | Exploitation | 6 | false | true | [VulnerabilityScanning, ApiSecurity] | ["T1190"] |
| 94 | github-dorks | Safe | Scanning | OSINT | 1 | false | true | [OsintDiscovery, SecretDiscovery] | [] |
| 95 | h2csmuggler | Medium | Scanning | Web | 1 | false | true | [HTTPRequestSmuggling] | [] |
| 96 | CdnCheckScanner | Safe | Scanning | Reconnaissance | 1 | false | true | [CdnDetection] | [] |
| 97 | TlsxScanner | Safe | Scanning | Reconnaissance | 2 | false | true | [TlsFingerprinting] | [] |
| 98 | ClairvoyanceScanner | Safe | Exploitation | Web | 5 | false | true | [GraphQL] | [] |
| 99 | GhauriScanner | Medium | Exploitation | Exploitation | 10 | false | true | [SqlInjection] | ["T1190"] |
| 100 | SsrfmapScanner | Medium | Exploitation | Exploitation | 15 | false | true | [VulnerabilityScanning] | ["T1557.002"] |
| 101 | NoSqlMapScanner | Medium | Exploitation | Exploitation | 10 | false | true | [VulnerabilityScanning] | ["T1190"] |
| 102 | GopherusScanner | Low | Exploitation | Exploitation | 5 | false | true | [VulnerabilityScanning] | ["T1557.002"] |
| 103 | KxssScanner | Low | Exploitation | Vulnerability | 3 | false | true | [XssScanning] | ["T1190"] |
| 104 | S3Scanner | Low | Discovery | Enumeration | 5 | false | true | [CloudAudit] | ["T1530"] |
| 105 | CloudMetadataExtractor | Critical | Exploitation | Exploitation | 5 | false | true | [VulnerabilityScanning] | ["T1552.005"] |
| 106 | azurehound | High | PostExploitation | Windows | 10 | false | false | [IAMAssessment, ActiveDirectory] | ["T1087.004"] |
| 107 | roadrecon | High | PostExploitation | Windows | 8 | false | false | [IAMAssessment] | ["T1087.004"] |
| 108 | NvdMonitor | Safe | Passive | Intelligence | 0 | false | true | [OsintDiscovery, InformationGathering] | [] |
| 109 | JwtForgeScanner | Medium | Scanning | Exploitation | 1 | false | true | [] | [] |
| 110 | JwksDiscoveryScanner | Safe | Scanning | Enumeration | 1 | false | true | [ApiSecurity] | [] |
| 111 | CorsTokenExfiltrator | Medium | Exploitation | Exploitation | 1 | false | true | [VulnerabilityScanning] | [] |
| 112 | DnsHijackVerifier | Safe | Scanning | Verification | 1 | false | true | [VulnerabilityScanning] | [] |
| 113 | SecretValidator | Safe | Scanning | Verification | 1 | false | true | [VulnerabilityScanning] | [] |
| 114 | GarakScanner | High | Exploitation | AI/Exploitation | 8 | false | true | [VulnerabilityScanning] | ["T1566"] |
| 115 | PromptmapScanner | Medium | Exploitation | AI/Exploitation | 5 | false | true | [VulnerabilityScanning] | ["T1566"] |
| 116 | LLMFuzzerScanner | Medium | Exploitation | AI/Exploitation | 6 | false | true | [VulnerabilityScanning] | ["T1499"] |
| 117 | PyRITScanner | High | Exploitation | Exploitation/AI | 15 | false | true | [VulnerabilityScanning] | ["T1592"] |
| 118 | PromptfooScanner | Medium | Exploitation | Exploitation/AI | 8 | false | true | [VulnerabilityScanning] | ["T1592"] |
| 119 | PromptInjectScanner | Medium | Exploitation | Exploitation/AI | 5 | false | true | [VulnerabilityScanning] | ["T1592"] |
| 120 | VigilScanner | Low | Exploitation | AI/LLM Security | 1 | false | true | [VulnerabilityScanning] | [] |
| 121 | ModelScanScanner | Medium | Exploitation | AI/ML Security | 1 | false | true | [VulnerabilityScanning] | [] |
| 122 | RebuffScanner | Low | Exploitation | AI/LLM Security | 1 | false | true | [VulnerabilityScanning] | [] |
| 123 | SyftScanner | Low | Scanning | Compliance | 5 | false | false | [VulnerabilityScanning] | ["T1584"] |
| 124 | GrypeScanner | Medium | Scanning | Compliance | 8 | false | false | [VulnerabilityScanning] | ["T1588.006"] |
| 125 | CosignScanner | Medium | Scanning | Compliance | 3 | false | false | [VulnerabilityScanning] | ["T1553"] |
| 126 | APKLeaksScanner | Low | Scanning | Mobile | 2 | false | true | [] | [] |
| 127 | ApktoolScanner | Low | Scanning | Mobile | 1 | false | true | [SecurityAuditing] | ["T1589"] |
| 128 | JadxScanner | Low | Scanning | Mobile | 2 | false | true | [SecurityAuditing] | ["T1589"] |
| 129 | DrozerScanner | Medium | Scanning | Mobile | 3 | false | true | [SecurityAuditing] | ["T1406"] |
| 130 | FridaScanner | Medium | Scanning | Mobile | 4 | false | true | [VulnerabilityScanning] | ["T1406"] |
| 131 | ObjectionScanner | Medium | Scanning | Mobile | 4 | false | true | [VulnerabilityScanning] | ["T1406"] |
| 132 | MarianaTrenchScanner | High | Scanning | Mobile | 5 | false | true | [SecurityAuditing, VulnerabilityScanning] | ["T1406"] |

## Auditoría Detallada de Discovery Plugins

| # | Name | Risk Level | Scan Layer | Category | Cost | Is Destructive | Poc Mode | Capabilities | Mitre Attacks |
|---|---|---|---|---|---|---|---|---|---|
| 133 | SovereignReconScanner | Safe | Passive | Osint | 10 | false | true | [SubdomainEnumeration, HistoricalRecon, OsintDiscovery] | [] |
| 134 | OsintScanner | Safe | Passive | Reconnaissance | 5 | false | false | [VulnerabilityScanning] | [] |
| 135 | SubfinderScanner | Safe | Passive | Reconnaissance | 5 | false | false | [SubdomainEnumeration] | [] |
| 136 | AmassScanner | Safe | Passive | Reconnaissance | 5 | false | false | [SubdomainEnumeration, OsintDiscovery] | [] |
| 137 | UncoverScanner | Safe | Passive | Reconnaissance | 5 | false | false | [VulnerabilityScanning] | [] |
| 138 | AlterXScanner | Safe | Discovery | Reconnaissance | 2 | false | true | [SubdomainEnumeration] | ["T1583.001"] |
| 139 | puredns | Safe | Passive | Reconnaissance | 4 | false | true | [SubdomainEnumeration] | ["T1589.001"] |
| 140 | BBScopeScanner | Safe | Passive | Reconnaissance | 10 | false | false | [ScopeExtraction] | [] |
| 141 | ShufflednsScanner | Safe | Passive | Reconnaissance | 8 | false | true | [SubdomainEnumeration] | ["T1589.001"] |
| 142 | AsnmapScanner | Safe | Passive | Reconnaissance | 2 | false | true | [AsnMapping] | [] |

## Estadísticas de Valores por Defecto o Potenciales Brechas (Leakage)

- Plugins con `risk_level` en Medium (por defecto): 76
- Plugins con `layer` en Scanning (por defecto): 63
- Plugins con `category` en "General" (por defecto): 1
- Plugins con `cost` en 1 (por defecto): 21
- Plugins con `is_destructive` en false (por defecto): 142
- Plugins con `poc_mode` en true (por defecto): 83
- Plugins con `capabilities` vacíos (leakage real): 7
