# PRD: ARES Agentic Framework (AAF)

**Product Requirements Document**
**DAEMON Blockint Technologies — ARES Brand**
**Version 1.0 | Juni 2026**
**Status: DRAFT — For Review**

---

## 1. Executive Summary

ARES Agentic Framework (AAF) adalah lapisan orkestrasi multi-agent independen yang dibangun di atas fondasi deterministik ARES V3. Framework ini menggabungkan tiga metodologi:

1. **Crystalline Cognitive Memory** — Sistem memori kognitif 5-layer berbasis ACT-R theory (`arc-agi-crystalline`, 2026): terbukti meningkatkan performa dari 57% → 97.69% pada ARC-AGI-3 hanya dengan menambahkan memory scaffold tanpa mengganti model.
2. **MDASH Multi-Agent Pipeline** — Arsitektur Auditor → Debater → Prover cohort dari Microsoft MDASH (CyberGym score 88.45%, 16 CVE baru) yang membuktikan bahwa pipeline multi-agen menemukan kerentanan lintas-file yang tidak terlihat oleh model tunggal.
3. **ARES V3 Deterministic Core** — Pipeline 4-fase (Regex → AST → Taint → Judge) dengan 97% recall dan $0 API cost sebagai ground-truth input layer.

**Core thesis:** ARES V3 sudah menjadi mesin deteksi terbaik di kelasnya. AAF tidak mengganti core — ia mengorkestrasi agen AI *di atas* output deterministik tersebut untuk mengisi tiga gap yang tidak bisa diselesaikan oleh static analysis murni.

**Provider LLM:** OpenRouter dengan dynamic model routing per agent role.

---

## 2. Problem Statement

### 2.1 Gap yang Tidak Bisa Diselesaikan Static Analysis

| Gap | Deskripsi | Dampak |
|-----|-----------|--------|
| **FP Residual** | Precision 0.83 → ~17% findings masih False Positive | Tim audit buang waktu verifikasi manual |
| **Zero Cross-Protocol Learning** | Setiap scan mulai dari nol; insight audit Wormhole tidak mempengaruhi scan Mango-v4 | Kesalahan yang sama berulang |
| **Kandidat ≠ Bukti** | ARES V3 menghasilkan *kandidat finding*, bukan *proven finding* dengan PoC | Klien butuh validasi tambahan yang mahal |
| **Blind Spot Semantik** | Taint analysis tidak bisa reasoning kondisi exploit kontekstual (misal: multi-tx reentrancy, cross-program state dependency) | Miss pada vuln kompleks |

### 2.2 Root Cause

Static analysis beroperasi pada *struktur kode*, bukan *intent eksekusi*. Kerentanan seperti arbitrary CPI dengan conditional path, initialization frontrunning dengan timing dependency, atau reentrancy via CPI chain membutuhkan **multi-step temporal reasoning** yang tidak bisa dikodifikasikan dalam rules deterministik.

---

## 3. Tujuan Produk & Success Metrics

| Tujuan | Metrik | Target |
|--------|--------|--------|
| Eliminasi residual FP | Precision post-AAF | ≥ 0.95 (dari 0.83 baseline) |
| Cross-protocol memory transfer | Lessons dari audit N diterapkan N+1 | ≥ 80% relevant principles recalled |
| Auto PoC generation | % proven findings dengan PoC draft | ≥ 60% untuk Critical/High |
| Cost control | Biaya LLM per audit penuh | < $2.00 via OpenRouter routing |
| Latency | Total pipeline waktu per protokol | < 3 menit |
| Recall preservation | Recall tidak turun dari baseline | Recall ≥ 0.97 (tidak boleh turun) |

> **Prinsip utama:** AAF hanya boleh *meningkatkan precision* dan *menambah context*. Ia tidak boleh memfilter finding dari ARES V3 core sebelum ARES ARBITER selesai bekerja. Recall baseline harus dipertahankan.

---

## 4. Arsitektur Sistem

### 4.1 Diagram Sistem

```
┌──────────────────────────────────────────────────────────────────┐
│                    ARES AGENTIC FRAMEWORK (AAF)                  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │               ARES CONDUCTOR (Orchestrator)              │   │
│  │                   Rust + Tokio async                     │   │
│  │                                                          │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌──────┐  │   │
│  │  │   ARES    │  │   ARES    │  │   ARES    │  │ARES  │  │   │
│  │  │   RECON   │→ │  ARBITER  │→ │ SENTINEL  │→ │FORGE │  │   │
│  │  │ (Auditor) │  │ (Debater) │  │ (Prover)  │  │(Mem) │  │   │
│  │  └───────────┘  └───────────┘  └───────────┘  └──────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌───────────────────────────▼──────────────────────────────┐   │
│  │                  ARES MEMORY VAULT                       │   │
│  │  Redis (Episodic) │ SQLite+Vec (Semantic/Analogical)     │   │
│  │  Markdown Files (Procedural/Principles)                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌───────────────────────────▼──────────────────────────────┐   │
│  │                   ARES GATEWAY                           │   │
│  │          OpenRouter — Dynamic Model Routing              │   │
│  │  Fast: Gemini Flash │ Deep: Claude Sonnet/Opus           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌───────────────────────────▼──────────────────────────────┐   │
│  │              ARES V3 CORE ENGINE (Unchanged)             │   │
│  │           Regex → AST → Taint → Deterministic Judge      │   │
│  │              97% Recall | $0 Cost | < 5 sec              │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

### 4.2 Prinsip Desain

1. **Determinism First** — ARES V3 core tidak disentuh. AAF beroperasi di atas output-nya, bukan menggantikannya.
2. **Validation as Pipeline** — "Kandidat finding" dan "proven finding" adalah objek yang berbeda. ARES ARBITER wajib memisahkan keduanya sebelum ARES SENTINEL bekerja.
3. **Memory is the Moat** — Model bisa diganti kapan saja. ARES Memory Vault adalah aset jangka panjang yang tumbuh setiap audit.
4. **Cost-Aware Routing** — Tidak semua task butuh model terkuat. ARES GATEWAY meroute berdasarkan kompleksitas task.
5. **Fail-Safe Degradation** — Jika semua komponen agentic gagal (timeout, API error), ARES V3 core tetap menghasilkan output lengkap tanpa AAF.

---

## 5. Definisi Komponen

### 5.1 ARES CONDUCTOR

**Peran:** Orchestrator utama. Mengelola lifecycle semua agen, message passing, state machine audit, dan budget enforcement.

**Teknologi:** Rust + Tokio, tidak ada dependency framework agent eksternal.

**State Machine:**

```
Idle → Scanning → Reconning → Arbitrating → Proving → Forging → Reporting
                                                ↑                    │
                                                └────────────────────┘
                                                  (jika ada findings baru
                                                   yang perlu di-re-probe)
```

Setiap transisi di-log ke audit trail immutable. Tidak ada state yang bisa di-skip.

**Interface:**

```rust
pub struct AresConductor {
    pub vault: Arc<AresVault>,
    pub gateway: Arc<AresGateway>,
    pub config: AresAgenticConfig,
    pub state: AresState,
    pub budget_tracker: BudgetTracker,  // enforce max_cost_per_audit
}

impl AresConductor {
    pub async fn run_audit(&mut self, target: &Path) -> Result<AresAuditReport>;
    pub async fn get_state(&self) -> AresState;
    pub fn remaining_budget(&self) -> f64;
}
```

---

### 5.2 ARES RECON

**Peran:** Auditor Agent. Menerima `Vec<CandidateFinding>` dari ARES V3 core dan memperkaya setiap finding dengan konteks semantik.

**Inspirasi:** MDASH Auditor cohort — menghasilkan kandidat, bukan keputusan final.

**Dijalankan:** Paralel, hingga `max_parallel_recon` instance (default: 8). Setiap instance menangani satu finding cluster (grouped by file/module).

**Memory Injection:** Sebelum setiap call, ARES RECON menerima context dari ARES Memory Vault:
- `episodic`: 10 episode terbaru dari protokol serupa
- `semantic`: 5 pattern paling mirip dari semantic DB
- `principles`: Full principles.md
- `analogical`: Protokol analog yang pernah diaudit

**Prompt Template:**

```
Kamu adalah ARES RECON, spesialis analisis kerentanan Solana.

## Memory Context
{episodic_context}
{semantic_context}
{principles}

## Kandidat Finding dari ARES V3 Core
{candidate_finding_json}

## Tugasmu
1. Jelaskan mengapa pattern ini berpotensi menjadi kerentanan
2. Identifikasi kondisi exploit yang diperlukan
3. Berikan severity reasoning (Critical/High/Medium/Low/Info)
4. Tandai confidence score (0.0-1.0)

Output format: JSON sesuai EnrichedFinding schema.
JANGAN buat keputusan final. Output adalah kandidat yang akan di-review ARES ARBITER.
```

**Output:** `Vec<EnrichedFinding>` dengan field tambahan: `enrichment_reasoning`, `exploit_conditions`, `confidence_score`.

---

### 5.3 ARES ARBITER

**Peran:** Debater Agent. Aktif membantah setiap EnrichedFinding dari ARES RECON.

**Inspirasi Langsung:** MDASH Debater cohort yang terbukti mengeliminasi false positives pada CVE-2026-33827 dan CVE-2026-33824 melalui adversarial reasoning. Juga identik dengan Crystalline Phase 5 verification loop yang menolak hasil self-reported.

**Metodologi:** Chain-of-thought adversarial:
1. *"Dalam kondisi apa ini BUKAN kerentanan?"*
2. *"Apakah ada Anchor constraint yang terlewat taint analysis?"*
3. *"Apakah ada mitigasi runtime yang tidak terlihat dari source?"*
4. *"Apakah confidence score ARES RECON justified?"*

**Output states:**
- `PROVEN` — Finding lolos semua bantahan, dilanjutkan ke ARES SENTINEL
- `REFUTED` — Finding terbukti FP, di-archive dengan reasoning
- `NEEDS_EVIDENCE` — Finding butuh data tambahan (on-chain state, runtime trace)

**Prompt Template:**

```
Kamu adalah ARES ARBITER. Tugasmu adalah membantah finding berikut.
Kamu harus menemukan alasan mengapa ini BUKAN kerentanan.

## Finding dari ARES RECON
{enriched_finding_json}

## Instruksi
- Argumentasikan MELAWAN finding ini
- Cari kondisi di mana false positive terjadi
- Periksa apakah Anchor macro constraints sudah cukup sebagai mitigasi
- Berikan verdict: PROVEN | REFUTED | NEEDS_EVIDENCE
- Berikan arbiter_reasoning yang detail

Jika kamu tidak bisa menemukan alasan untuk membantah setelah analisis menyeluruh,
berikan verdict PROVEN dengan penjelasan mengapa bantahan gagal.
```

---

### 5.4 ARES SENTINEL

**Peran:** Prover Agent. Bekerja eksklusif pada findings dengan status `PROVEN` dari ARES ARBITER.

**Inspirasi:** MDASH dynamic proof construction — generating working exploit proof untuk validasi CVE. Crystalline Solve Phase — menghasilkan solver yang bisa di-replay.

**Scope:** Hanya diaktifkan untuk severity `Critical` dan `High` (konfigurabel via `sentinel_enabled_severity`).

**Output:** Draft PoC dalam bentuk Rust test harness:

```rust
#[cfg(test)]
mod ares_sentinel_poc {
    // ARES SENTINEL generated PoC — DRAFT, requires manual verification
    // Finding: {finding_id} — {finding_type}
    // Generated: {timestamp}
    
    #[tokio::test]
    async fn exploit_{finding_id}() {
        // Setup: {exploit_conditions}
        // ...
    }
}
```

**Penting:** Semua output ARES SENTINEL di-watermark sebagai `DRAFT — REQUIRES MANUAL VERIFICATION`. ARES SENTINEL tidak mengklaim PoC-nya fully working.

---

### 5.5 ARES FORGE

**Peran:** Memory Agent. Berjalan sebagai background task pasca-audit. Menulis lessons ke ARES Memory Vault.

**Inspirasi Langsung:** Crystalline Cognitive Memory 5-layer ACT-R — *"Crystalline doesn't memorize solutions, it memorizes why things fail and how to overcome them."*

**5 Layer yang Ditulis:**

| Layer | Trigger | Contoh Konten |
|-------|---------|---------------|
| `episodic` | Setiap audit selesai | "Audit Mango-v4 2026-06-09: pattern safe-borrow di baris 142 menghasilkan FP ownership-check karena ada `has_one` constraint tersembunyi di macro expansion" |
| `semantic` | Finding PROVEN baru | "DeFi lending protocol: pola `borrow_reserve.owner != program_id` bisa jadi FP jika diikuti `has_one = lending_market` constraint" |
| `procedural` | ARBITER REFUTED finding | "Prosedur: sebelum report ownership-check pada SPL token account, selalu expand Anchor macro untuk cek implicit constraints" |
| `analogical` | Protokol baru mirip protokol lama | "Axelar bridge struct (CPI pattern) analogous dengan Wormhole — lessons Wormhole apply" |
| `principles` | Pola berulang ≥ 3x di episodic | "PRINSIP: Selalu validate discriminator sebelum report type-cosplay pada Anchor accounts" |

---

## 6. ARES Memory Vault

### 6.1 Storage Architecture

```
ares-vault/
├── hot/                          # Redis — episodic memory (fast R/W)
│   └── episodes/                 # TTL: 90 hari per entry
├── cold/                         # SQLite — semantic & analogical
│   ├── ares_semantic.db          # Vector embeddings + metadata
│   └── ares_analogical.db        # Protocol similarity graph
└── principles/                   # Plain Markdown — slow-changing wisdom
    ├── procedural.md             # "Kalau X, lakukan Y"
    └── principles.md             # Hard rules, tidak boleh dilanggar
```

### 6.2 Memory Retrieval Interface

```rust
pub struct AresVault {
    redis: RedisClient,
    sqlite: SqlitePool,
    principles_dir: PathBuf,
}

impl AresVault {
    // Episodic: ambil N episode terbaru dari protokol serupa
    pub async fn get_recent_episodes(&self, protocol: &Protocol, n: usize) 
        -> Vec<Episode>;
    
    // Semantic: vector similarity search
    pub async fn semantic_search(&self, patterns: &[Pattern], top_k: usize) 
        -> Vec<SemanticEntry>;
    
    // Analogical: cari protokol analog berdasarkan struktural similarity
    pub async fn find_analogues(&self, protocol_type: &ProtocolType) 
        -> Vec<Analogue>;
    
    // Principles: load semua hard rules
    pub async fn load_principles(&self) -> String;
    
    // Write (dipanggil oleh ARES FORGE)
    pub async fn write_episode(&self, episode: Episode) -> Result<()>;
    pub async fn write_semantic(&self, entry: SemanticEntry) -> Result<()>;
    pub async fn append_principle(&self, principle: &str) -> Result<()>;
}
```

---

## 7. ARES GATEWAY — OpenRouter Integration

### 7.1 Dynamic Model Routing Table

| Agent | Model Default | Alasan Pemilihan |
|-------|--------------|-----------------|
| ARES RECON | `google/gemini-flash-1.5` | Fast, cheap, cukup untuk enrichment dan context extraction |
| ARES ARBITER | `anthropic/claude-sonnet-4-5` | Reasoning kuat, adversarial thinking, cost-balanced |
| ARES SENTINEL | `anthropic/claude-opus-4-5` | Model terkuat untuk code generation dan PoC construction |
| ARES FORGE | `mistralai/mistral-small-3.1` | Lightweight summarization, memory write tidak butuh model besar |

> Semua model dapat di-override via `ares.toml` `[agentic.routing]` section.

### 7.2 Interface

```rust
pub struct AresGateway {
    base_url: String,           // "https://openrouter.ai/api/v1"
    api_key: String,            // OPENROUTER_API_KEY env
    routing_table: HashMap<AgentRole, ModelProfile>,
    http_client: reqwest::Client,
}

impl AresGateway {
    pub async fn complete(
        &self, 
        role: AgentRole, 
        prompt: String,
        max_tokens: usize,
    ) -> Result<(String, TokenUsage), AresGatewayError>;
    
    pub fn estimate_cost(&self, role: AgentRole, input_tokens: usize) -> f64;
}
```

### 7.3 Budget Enforcement

ARES CONDUCTOR memaintain `BudgetTracker` real-time. Jika `remaining_budget <= 0`, pipeline berhenti di state saat ini dan menghasilkan partial report dengan semua findings yang sudah diproses.

---

## 8. Pipeline Eksekusi End-to-End

```
INPUT: Solana program source directory
           │
           ▼
┌─────────────────────────┐
│     ARES V3 CORE        │  Fase 1-4: Regex → AST → Taint → Judge
│   (Deterministik)       │  Output: Vec<CandidateFinding>
│   < 5 detik, $0 cost    │  RECALL DIPERTAHANKAN PENUH
└────────────┬────────────┘
             │  inject: episodic + semantic + principles dari ARES VAULT
             ▼
┌─────────────────────────┐
│      ARES RECON         │  Paralel, hingga 8 instance
│  (Enrichment Agent)     │  Model: Gemini Flash
│  ~30-60 detik           │  Output: Vec<EnrichedFinding>
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│     ARES ARBITER        │  Sequential per finding
│  (Debate/Filter Agent)  │  Model: Claude Sonnet
│  ~45-90 detik           │  Output: Vec<ProvenFinding> + Vec<RefutedFinding>
└────────────┬────────────┘
             │  hanya ProvenFindings (severity Critical/High)
             ▼
┌─────────────────────────┐
│     ARES SENTINEL       │  Async, hanya Critical/High
│  (PoC Generator)        │  Model: Claude Opus
│  ~30-60 detik           │  Output: Vec<ProvenFinding+PoCDraft>
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│      ARES FORGE         │  Background task, non-blocking
│  (Memory Writer)        │  Model: Mistral Small
│  ~15-30 detik           │  Update: 5-layer ARES VAULT
└────────────┬────────────┘
             │
             ▼
OUTPUT: ARES Audit Report (JSON + MD + HTML)
        + PoC Drafts (Rust test harness)
        + ARES Vault updated (lessons persisted)
        + Cost breakdown per agent
```

---

## 9. Output Report Schema

AAF memperluas format ARES V3 JSON dengan kolom agentic:

```json
{
  "ares_version": "3.1.0-agentic",
  "audit_id": "ARES-2026-06-09-mango-v4",
  "pipeline": {
    "core_scan_ms": 3200,
    "recon_ms": 45000,
    "arbiter_ms": 78000,
    "sentinel_ms": 42000,
    "forge_ms": 12000,
    "total_cost_usd": 1.43
  },
  "summary": {
    "total_candidates": 18,
    "proven": 12,
    "refuted": 6,
    "with_poc_draft": 7
  },
  "findings": [
    {
      "id": "ARES-2026-001",
      "type": "arbitrary-cpi",
      "severity": "Critical",
      "file": "src/processor.rs",
      "line": 142,
      "status": "PROVEN",
      "recon_confidence": 0.92,
      "recon_reasoning": "...",
      "exploit_conditions": ["caller controls program_id", "no signer check on CPI"],
      "arbiter_verdict": "PROVEN",
      "arbiter_reasoning": "Bantahan gagal: tidak ada implicit constraint yang bisa mitigasi CPI tanpa program_id validation pada path ini",
      "poc_draft_path": "ares-sentinel-pocs/ARES-2026-001.rs",
      "poc_status": "DRAFT_UNVERIFIED"
    },
    {
      "id": "ARES-2026-007",
      "type": "ownership-check",
      "severity": "Medium",
      "status": "REFUTED",
      "arbiter_verdict": "REFUTED",
      "arbiter_reasoning": "has_one = lending_market constraint pada macro expansion line 89 sudah memvalidasi ownership secara implicit. ARES V3 taint analysis tidak melihat macro expansion ini."
    }
  ]
}
```

---

## 10. Konfigurasi `ares.toml` — Ekstensi Agentic

```toml
# Tambahan pada ares.toml.template existing

[agentic]
enabled = true
provider = "openrouter"
base_url = "https://openrouter.ai/api/v1"
api_key_env = "OPENROUTER_API_KEY"

[agentic.routing]
recon    = "google/gemini-flash-1.5"
arbiter  = "anthropic/claude-sonnet-4-5"
sentinel = "anthropic/claude-opus-4-5"
forge    = "mistralai/mistral-small-3.1"

[agentic.vault]
redis_url         = "redis://localhost:6379"
sqlite_path       = "./vault/cold/ares.db"
principles_dir    = "./vault/principles"
episode_ttl_days  = 90

[agentic.limits]
max_parallel_recon          = 8
arbiter_timeout_sec         = 30
sentinel_enabled_severity   = ["Critical", "High"]
max_cost_per_audit_usd      = 2.00
fail_safe_on_budget_exceed  = true   # jika true: partial report, bukan error

[agentic.output]
include_poc_drafts     = true
include_refuted        = true   # tampilkan refuted findings dengan reasoning
poc_output_dir         = "./ares-sentinel-pocs"
```

---

## 11. Struktur Codebase

```
ARES-v3/
├── crates/
│   ├── ares-cli/           # EXISTING — CLI entry point (update: tambah `ares agentic` subcommand)
│   ├── ares-core/          # EXISTING — static analysis engine (tidak disentuh)
│   ├── ares-mapper/        # EXISTING — AST + taint (tidak disentuh)
│   ├── ares-policy/        # EXISTING — policy guardrails (tidak disentuh)
│   ├── ares-trident/       # EXISTING — fuzzer integration (tidak disentuh)
│   │
│   ├── ares-conductor/     # NEW — orchestrator, state machine, budget tracker
│   ├── ares-recon/         # NEW — auditor agent, parallel enrichment
│   ├── ares-arbiter/       # NEW — debater agent, adversarial filter
│   ├── ares-sentinel/      # NEW — prover agent, PoC draft generator
│   ├── ares-forge/         # NEW — memory writer, 5-layer vault updater
│   ├── ares-vault/         # NEW — memory store (Redis + SQLite + Markdown)
│   └── ares-gateway/       # NEW — OpenRouter client, model router, budget tracker
│
├── vault/                  # NEW — runtime memory storage (gitignored)
│   ├── hot/                # Redis episodic snapshots (backup)
│   ├── cold/               # SQLite databases
│   └── principles/         # Markdown principle files
│       ├── procedural.md
│       └── principles.md
│
├── ares-sentinel-pocs/     # NEW — generated PoC drafts (gitignored)
│
├── docs/
│   ├── paper/              # EXISTING
│   └── PRD-ARES-Agentic-Framework.md  # THIS FILE
│
├── ares.toml.template      # EXISTING + updated dengan [agentic] section
└── ares-policy.toml.template  # EXISTING (tidak disentuh)
```

---

## 12. Dependency Baru

```toml
# Cargo.toml additions

[dependencies]
# Async runtime (sudah ada via tokio)
tokio = { version = "1", features = ["full"] }

# HTTP client untuk OpenRouter
reqwest = { version = "0.11", features = ["json", "rustls-tls"] }

# Redis client untuk episodic memory
redis = { version = "0.23", features = ["tokio-comp", "connection-manager"] }

# SQLite untuk semantic/analogical memory
sqlx = { version = "0.7", features = ["sqlite", "runtime-tokio-rustls"] }

# Vector embeddings (local, tanpa API)
fastembed = "3"

# Serialisasi (sudah ada)
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

> **Catatan:** Tidak ada dependency LangChain, LangGraph, atau framework agent eksternal. Semua orkestrasi adalah pure Rust.

---

## 13. CLI Interface — Perintah Baru

```bash
# Mode agentic penuh (ARES V3 core + AAF pipeline)
ares scan --target ./program --agentic

# Mode agentic dengan budget custom
ares scan --target ./program --agentic --max-cost 1.50

# Hanya tampilkan proven findings (filter refuted)
ares scan --target ./program --agentic --proven-only

# Jalankan hanya ARES RECON + ARBITER (tanpa PoC generation)
ares scan --target ./program --agentic --no-sentinel

# Inspect ARES Memory Vault
ares vault list --type episodic --last 10
ares vault list --type principles
ares vault clear --type episodic --older-than 30d

# Test ARES GATEWAY (verifikasi OpenRouter connectivity)
ares gateway test --role recon
```

---

## 14. Roadmap Implementasi

### Phase 1 — Foundation (2 minggu)
- [ ] `ares-gateway`: OpenRouter client dengan model routing
- [ ] `ares-vault`: Redis + SQLite storage dengan interface
- [ ] `ares-conductor`: State machine dasar + budget tracker
- [ ] Update `ares-cli`: tambah `--agentic` flag

### Phase 2 — Core Agents (2 minggu)
- [ ] `ares-recon`: Parallel enrichment agent
- [ ] `ares-arbiter`: Adversarial debate agent
- [ ] Integration test: ARES V3 → RECON → ARBITER pipeline
- [ ] Validate: recall tidak turun dari baseline 0.97

### Phase 3 — Advanced Agents (1 minggu)
- [ ] `ares-sentinel`: PoC draft generator
- [ ] `ares-forge`: 5-layer memory writer
- [ ] End-to-end pipeline test pada 5 benchmark protocols

### Phase 4 — Validation & Tuning (1 minggu)
- [ ] Benchmark ulang 20 protokol dengan AAF enabled
- [ ] Validate precision improvement: 0.83 → ≥ 0.95
- [ ] Cost profiling per protokol
- [ ] Documentation update

---

## 15. Risk & Mitigasi

| Risk | Probabilitas | Dampak | Mitigasi |
|------|-------------|--------|---------|
| ARBITER over-refutes (recall turun) | Medium | High | Benchmark recall setiap sprint; revert jika < 0.97 |
| OpenRouter rate limits | Low | Medium | Exponential backoff + fallback model routing |
| Redis tidak tersedia | Low | Low | Fail-safe: jalankan tanpa episodic memory |
| SENTINEL PoC misleading | Medium | Medium | Hard watermark DRAFT; manual review required |
| Cost overrun per audit | Low | Medium | Hard limit via BudgetTracker + fail_safe_on_budget_exceed |

---

## 16. Non-Goals (Tidak Termasuk v1.0)

- **Bukan:** Real-time on-chain monitoring (domain ARES v4+)
- **Bukan:** Automated exploit deployment atau live testing
- **Bukan:** Multi-chain support (EVM, Move) — fokus Solana
- **Bukan:** SaaS/cloud deployment — local-first

---

## Authors & Acknowledgements

**Dibuat oleh:** Nyoko Karma Nugroho (Daemon Protocol)

**Metodologi dari:**
- `arc-agi-crystalline` by Paolo C — Crystalline Cognitive Memory architecture
- Microsoft MDASH (Security Blog, May 2026) — Multi-agent Auditor/Debater/Prover topology
- ARES V3 — Deterministic static analysis baseline (DAEMON Blockint Technologies)

---

*ARES Agentic Framework — Built on determinism, elevated by memory.*
