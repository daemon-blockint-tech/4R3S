# ARES V3: External Tools Classification

> Document version: 2.0  
> Date: 2026-05-08  
> Scope: All external tools referenced in `ARES-V3_Overview.md` + `Resources.md` + research-derived additions  
> **Note**: `Resources.md` is the LIVING REFERENCE document. It is frequently updated and contains the most comprehensive tool/resource index. This classification MUST be re-synced whenever `Resources.md` is updated.

---

## Legend

| Kode | Arti |
|------|------|
| **INTEGRATED** | Tool akan dipanggil langsung oleh ARES V3 agent via CLI wrapper, MCP server, Docker container, atau API. |
| **REFERENCE** | Tool digunakan sebagai inspirasi arsitektur, pola, benchmark, atau pembanding — **tidak dipanggil runtime** oleh ARES V3. |
| **PLANNED** | Belum ada di codebase ARES V3 saat ini, tapi akan diintegrasikan di roadmap Phase 2–3. |
| **OPTIONAL** | Bisa diaktifkan untuk tier Enterprise atau mode advanced, bukan core path. |
| **LIVING** | Dokumen/link yang sering update — perlu re-sync manual ke klasifikasi ini setiap ada perubahan. |

---

## 1. Execution Engine Layer (Core Runtime)

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 1 | **Trident** (`Ackee-Blockchain/trident`) | **INTEGRATED** | Fuzzer / SVM | Property-based fuzzing, stateful fuzzing, Trident SVM execution. Ini adalah **mesin eksploitasi utama**. | CLI wrapper `trident fuzz run`, dipanggil via MCP tool `trident_cli`. |
| 2 | **Trident SVM** (bundled in Trident) | **INTEGRATED** | SVM Executor | Eksekusi transaksi Solana pada kecepatan ~12,000 tx/s dalam sandbox lokal. | Library call dari Rust wrapper ARES. |
| 3 | **Solana CLI** (`solana-test-validator`) | **INTEGRATED** | Validator Local | Fork mainnet state untuk sandbox ekonomi; jalankan localnet untuk PoC. | CLI wrapper, Docker container dengan `--clone` mainnet accounts. |
| 4 | **Anchor CLI** (`anchor test`, `anchor build`) | **INTEGRATED** | Build / Test | Build program, jalankan test PoC yang dihasilkan Exploit Constructor Agent. | CLI wrapper dalam Docker sandbox. |
| 5 | **solana-program-library (SPL)** | **INTEGRATED** | Token / Standard | CPI ke Token Program, Associated Token Account, etc. dalam test harness. | Rust dependency dalam generated test code. |

---

## 2. Static Analysis & Pre-Fuzzing Intelligence

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 6 | **IDLGuesser** (`sec3-service/IDLGuesser`) | **PLANNED** | IDL Parser | Reverse-engineer / parse IDL dari program yang tidak memiliki IDL eksplisit. Dipakai Mapper Agent saat IDL tidak tersedia. | API call atau CLI wrapper dalam fase mapping. |
| 7 | **sec3 X-Ray** (`sec3-product/x-ray`) | **OPTIONAL** | Static Analysis | Scanner kerentanan Solana (misalnya missing signer check, unsafe math). Dijalankan sebelum fuzzing untuk prioritisasi. | CLI wrapper; hasilnya jadi input Hypothesis Generator Agent. |
| 8 | **cargo-audit** (`docs.rs/cargo-audit`) | **INTEGRATED** | Dependency Audit | Scan `Cargo.lock` / `Cargo.toml` untuk known CVEs di dependency Rust. | CLI wrapper dipanggil saat `ares scan --deps`. |
| 9 | **cargo-geiger** (`crates.io/crates/cargo-geiger`) | **PLANNED** | Unsafe Rust Detector | Hitung dan visualisasikan penggunaan `unsafe` Rust di codebase. Bantu Mapper Agent menandai attack surface. | CLI wrapper; output JSON diparse untuk risk score. |
| 10 | **Rust Analyzer / `cargo check`** | **INTEGRATED** | LSP / Compiler | Compile-time check, type inference, dan borrow-checker analysis untuk memahami data flow sebelum fuzzing. | Langsung via Rust toolchain; digunakan oleh Mapper Agent untuk AST building. |

---

## 3. Formal Verification & Advanced Reasoning

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 11 | **Kani** (`model-checking/kani`) | **PLANNED** | Formal Verification | Model checker Rust untuk membuktikan invariant secara matematis pada critical path (misalnya arithmetic, access control). | CLI wrapper `cargo kani`; digunakan oleh Fuzzer Orchestrator Agent untuk path yang sulit dicapai fuzzer. |
| 12 | **CBMC / CBMC Viewer / CBMC Starter Kit** (`model-checking/cbmc-*`) | **REFERENCE** | C Formal Verification | Model checker untuk C/C++. Tidak langsung relevan untuk Rust/Solana. | **Tidak diintegrasikan**. Referensi arsitektur untuk bagaimana menampilkan counter-example trace (mirip `cbmc-viewer`). |

---

## 4. Fuzzing Harness & Test Generation

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 13 | **test-fuzz** (`trailofbits/test-fuzz`) | **PLANNED** | Fuzzing Harness | Generate fuzzing harness dari unit test Rust secara otomatis. Dapat mempercepat Exploit Constructor Agent membuat seed test. | CLI wrapper / Rust macro expansion. |
| 14 | **necessist** (`trailofbits/necessist`) | **PLANNED** | Mutation Testing | Mutation testing untuk Rust & TypeScript. Menghapus statement satu per satu untuk cek apakah test masih pass — ukur kekuatan test suite. | CLI wrapper; digunakan di CI untuk memastikan PoC test tidak fragile. |
| 15 | **dylint** (`trailofbits/dylint`) | **REFERENCE** | Linting Framework | Framework linting Rust yang bisa custom. Referensi untuk bagaimana ARES Rules Engine bisa membuat custom lint rules. | **Tidak dipanggil langsung**. ARES akan punya engine custom sendiri yang terinspirasi dylint. |

---

## 5. Solana Audit & CTF Frameworks (PoC / Exploit Patterns)

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 16 | **sol-ctf-framework** (`otter-sec/sol-ctf-framework`) | **REFERENCE** | CTF Framework | Framework Rust untuk CTF Solana (OtterSec). Referensi pola attack template dan harness structure. | **Tidak dipanggil langsung**. ARES Exploit Constructor Agent akan menghasilkan code dengan pola serupa. |
| 17 | **solana-poc-framework** (`neodyme-labs/solana-poc-framework`) | **REFERENCE** | PoC Framework | Framework proof-of-concept Neodyme. Referensi untuk cara bangun transaksi sequence yang deterministic di local validator. | **Tidak dipanggil langsung**. ARES PoC output akan kompatibel dengan pola ini. |
| 18 | **checked-math** (`blockworks-foundation/checked-math`) | **REFERENCE** | Math Safety | Library Anchor untuk arithmetic checked. Referensi pola "secure code" yang seharusnya ada — kalau tidak ada, Hypothesis Generator Agent flag sebagai bug candidate. | **Tidak dipanggil langsung**. Hypothesis Generator menggunakan daftar "expected patterns" seperti ini. |
| 19 | **vipers** (`saber-hq/vipers`) | **REFERENCE** | Validation Macros | Macro validasi Anchor (misalnya `assert_keys_eq`, `assert_owned_by`). Referensi pola constraint yang seharusnya ada. | **Tidak dipanggil langsung**. Rules engine ARES akan punya rule set serupa. |

---

## 6. Verification & Build Integrity

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 20 | **otter-verify** (`otter-sec/otter-verify`) | **REFERENCE** | Verification | Verifikasi on-chain build Solana program cocok dengan source code. | **Tidak dipanggil langsung**. ARES Enterprise tier bisa integrasi opsional untuk final verification step. |
| 21 | **solana-verified-programs-api** (`otter-sec/solana-verified-programs-api`) | **REFERENCE** | Verified Builds API | API untuk cek apakah program sudah verified build. | **Tidak dipanggil langsung**. Referensi metadata yang bisa di enrich saat reporting. |
| 22 | **qemu-escape** (`otter-sec/qemu-escape`) | **REFERENCE** | Advanced Exploit | PoC escape QEMU (research advanced). | **Tidak dipanggil langsung**. Referensi untuk arsitektur sandbox isolation dan threat model. |

---

## 7. Policy Engine & Security Architecture (Referensi Arsitektur)

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 23 | **IronCurtain.dev** (`@provos/ironcurtain`) | **REFERENCE** | Policy Engine | Personal AI assistant dengan capability escalation dan sandbox policy. **Blueprint utama** untuk ARES Policy Engine. | **Tidak dipanggil langsung**. ARES akan rebuild konsep `constitution.md` + capability levels untuk domain Solana audit. |
| 24 | **Kubescape** (`kubescape/kubescape`) | **REFERENCE** | Kubernetes Security | Security scanner untuk Kubernetes cluster. | **Tidak relevan untuk Solana smart contract audit**. Mungkin dipakai hanya jika ARES deploy di K8s infrastructure tier Enterprise. |

---

## 8. Competitor / Benchmark (Referensi Metrik & UX)

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 25 | **Trident Arena** (`tridentarena.xyz`) | **REFERENCE** | Competitor / Benchmark | Baseline yang harus dilewati. Metodologi benchmark (6 protokol, 30 critical/high) diadopsi dan diperluas. | **Tidak dipanggil langsung**. ARES benchmark protocol akan menggunakan dataset yang sama + 50+ protokol tambahan. |
| 26 | **Trident Arena Benchmarks** (`Ackee-Blockchain/trident-arena-benchmarks`) | **REFERENCE** | Dataset / Benchmark | Repo benchmark hasil Trident Arena. Ground truth untuk evaluasi ARES V3. | **Tidak dipanggil langsung**. Dataset reference untuk scoring. |
| 27 | **Ackee Public Audit Reports** (`Ackee-Blockchain/public-audit-reports`) | **REFERENCE** | Audit Dataset | Laporan audit manual Ackee untuk training data dan pattern extraction. | **Tidak dipanggil langsung**. Training data untuk Reporter Agent dan Hypothesis Generator. |

---

## 9. AI Agent Skills & Workflow Patterns (Referensi Orkestrasi)

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 28 | **Trail of Bits Skills** (`skills.sh/trailofbits`) | **REFERENCE** | Agent Skills | Pola agent skill untuk security audit. | **Tidak dipanggil langsung**. Inspirasi untuk membangun MCP tools dan skill prompt. |
| 29 | **QEDGen Skills** (`skills.sh/qedgen`) | **REFERENCE** | Agent Skills | Pola agent skill untuk formal verification / proof generation. | **Tidak dipanggil langsung**. Referensi arsitektur Hypothesis Generator + Kani integration. |
| 30 | **zz-code-recon** (`sendaifun/skills/zz-code-recon`) | **REFERENCE** | Reconnaissance Skill | Skill reconnaissance codebase untuk AI agent. | **Tidak dipanggil langsung**. Referensi untuk Mapper Agent reconnaissance workflow. |
| 31 | **vulnhunter** (`sendaifun/skills/vulnhunter`) | **REFERENCE** | Vuln Discovery Skill | Skill hunting vulnerability untuk AI agent. | **Tidak dipanggil langsung**. Referensi untuk Hypothesis Generator Agent prompt engineering. |

---

## 10. Anthropic Research (Referensi Benchmark & Agent Architecture)

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 32 | **SCONE-bench** (`red.anthropic.com/2025/smart-contracts/`) | **REFERENCE** | Benchmark Methodology | Metodologi benchmark exploit smart contract: fork blockchain, saldo awal, exploit script, metric ekonomi. | **Tidak dipanggil langsung**. Blueprint untuk **Solana SCONE-bench** yang akan dibangun ARES. |
| 33 | **Opus 4.6 Zero-Day Methodology** (`red.anthropic.com/2026/zero-days/`) | **REFERENCE** | Agent Reasoning | Metodologi Opus 4.6: analisis git history, pattern matching fungsi berisiko, iterasi tool use. | **Tidak dipanggil langsung**. Direkomendasikan sebagai training prompt untuk Mapper Agent dan Hypothesis Generator Agent. |
| 34 | **Foundry** (`forge`, `cast`, `anvil`) | **REFERENCE** | EVM Toolchain | Toolchain EVM yang dipakai SCONE-bench. | **Tidak dipanggil langsung**. Referensi toolchain-equivalent untuk Solana: Trident CLI + Solana CLI + Anchor. |

---

## 11. UI / Interface (Referensi atau Tier Tertentu)

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 35 | **anchor-UI** (`pratikbuilds/anchor-UI`) | **REFERENCE** | UI Framework | UI untuk Anchor program deployment/management. | **Tidak dipanggil langsung**. Referensi UX untuk Web App tier ARES Enterprise jika ada dashboard interaktif. |
| 36 | **auditor-architecture-template** (`exo-tech-xyz/auditor-architecture-template`) | **REFERENCE** | Architecture Template | Template arsitektur auditor (tidak spesifik Solana). | **Tidak dipanggil langsung**. Referensi struktur dokumentasi dan modul untuk ARES architecture docs. |

---

## 12. Payment & Infrastructure (Referensi Tier Advanced)

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 37 | **mpp.dev / Tempo** | **REFERENCE** | Payment Gateway | Pay-as-you-go API payment dengan USDC/PathUSD. | **Tidak dipanggil langsung**. Referensi untuk tier ARES Enterprise jika ingin monetize API call per scan. |
| 38 | **Stripe** | **REFERENCE** | Payment Gateway | Pembayaran kartu kredit. | **Tidak dipanggil langsung**. Referensi untuk tier ARES Audit-Assist & Enterprise subscription. |

---

## 13. Agent Framework & SDK (Integrated / Reference)

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 40 | **Claude Code** (`anthropics/claude-code`) | **REFERENCE** | AI Agent Shell | Anthropic's agentic coding assistant. Referensi arsitektur agent yang bekerja di terminal dengan tool MCP. | **Tidak dipanggil langsung**. Referensi UX dan orkestrasi tool-use untuk ARES CLI agent. |
| 41 | **OpenCode** (`anomalyco/opencode`) | **REFERENCE** | Open-Source AI IDE | Open-source AI coding assistant. Referensi alternatif arsitektur agent yang bisa di-embed. | **Tidak dipanggil langsung**. Referensi SDK/API surface untuk tier ARES Enterprise. |
| 42 | **OpenTUI** (`anomalyco/opentui`) | **REFERENCE** | Terminal UI Framework | Framework TUI open-source untuk agent. Referensi untuk TUI layer ARES. | **Tidak dipanggil langsung**. Referensi teknis untuk TUI ARES (bersama `ratatui`). |
| 43 | **OpenRouter SDK** (`OpenRouterTeam/typescript-sdk`) | **PLANNED** | LLM Routing SDK | SDK untuk routing request ke multiple LLM providers (Claude, GPT, Llama, DeepSeek). | API client di ARES orchestrator untuk model failover dan cost optimization. |

---

## 14. Agent Skills & Prompt Libraries (Reference / Living)

| # | Tool / Repo | Status | Kategori | Peran dalam ARES V3 | Cara Integrasi |
|---|-------------|--------|----------|---------------------|----------------|
| 44 | **Trail of Bits Skills** (`skills.sh/trailofbits`) | **REFERENCE** | Security Agent Skills | Pola agent skill untuk security audit. | **Tidak dipanggil langsung**. Inspirasi untuk membangun MCP tools dan skill prompt. |
| 45 | **Trail of Bits — Solana Vulnerability Scanner** (`skills.sh/trailofbits/skills/solana-vulnerability-scanner`) | **REFERENCE** | Solana Skill | Skill spesifik Solana dari Trail of Bits. | **Tidak dipanggil langsung**. Training data / prompt template untuk Hypothesis Generator Agent. |
| 46 | **QEDGen / Solana Skills** (`skills.sh/qedgen/solana-skills`) | **REFERENCE** | Formal Verification Skill | Pola agent skill untuk formal verification / proof generation di Solana. | **Tidak dipanggil langsung**. Referensi arsitektur Hypothesis Generator + Kani integration. |
| 47 | **zz-code-recon** (`sendaifun/skills/zz-code-recon`) | **REFERENCE** | Reconnaissance Skill | Skill reconnaissance codebase untuk AI agent. | **Tidak dipanggil langsung**. Referensi untuk Mapper Agent reconnaissance workflow. |
| 48 | **vulnhunter** (`sendaifun/skills/vulnhunter`) | **REFERENCE** | Vuln Discovery Skill | Skill hunting vulnerability untuk AI agent. | **Tidak dipanggil langsung**. Referensi untuk Hypothesis Generator Agent prompt engineering. |
| 49 | **Vercel / Google Labs Skills** (`vercel-labs/agent-skills`, `google-labs-code/stitch-skills`, `vercel-labs/vercel-skills`, `google-labs-code/design.md`) | **REFERENCE** | Frontend/Design Skills | Skill libraries untuk UI/UX design dengan AI. | **Tidak dipanggil langsung**. Referensi untuk Web App tier ARES Enterprise jika ada dashboard design. |

---

## 15. Research Papers & Academic References (Living Reference)

| # | Paper / Link | Status | Topik | Relevansi untuk ARES V3 |
|---|-------------|--------|-------|------------------------|
| 50 | `arxiv:2409.01382` | **REFERENCE** | Smart Contract Security | Referensi metodologi analisis keamanan smart contract. |
| 51 | `arxiv:2401.11314` | **REFERENCE** | Fuzzing / Testing | Referensi teknik fuzzing atau property-based testing. |
| 52 | `arxiv:2301.10016` | **REFERENCE** | Blockchain Security | Referensi kerentanan blockchain atau audit methodology. |
| 53 | `arxiv:2304.02491` | **REFERENCE** | Formal Verification | Referensi verifikasi formal untuk smart contract. |
| 54 | `arxiv:1905.08085` | **REFERENCE** | Fuzzing Foundations | Referensi foundational fuzzing theory. |
| 55 | `arxiv:2404.12135v2` | **REFERENCE** | AI for Security | Referensi penggunaan AI untuk security auditing. |
| 56 | `arxiv:2410.09381` | **REFERENCE** | Agent Systems | Referensi multi-agent systems atau autonomous agents. |
| 57 | `arxiv:2309.03006` | **REFERENCE** | Solana / Rust | Referensi spesifik Solana program security atau Rust memory safety. |
| 58 | `arxiv:2304.06341` | **REFERENCE** | DeFi Security | Referensi keamanan protokol DeFi. |
| 59 | `arxiv:2301.03943` | **REFERENCE** | Economic Security | Referensi economic exploit atau MEV analysis. |
| 60 | `dl.acm.org/doi/pdf/10.1145/3643916.3644406` | **REFERENCE** | ACM Conference Paper | Referensi peer-reviewed research di domain security/fuzzing/blockchain. |
| 61 | `scholarworks.iu.edu` (thesis) | **REFERENCE** | Academic Thesis | Referensi thesis / dissertation terkait security atau blockchain. |
| 62 | `arxiv:2406.13599` | **REFERENCE** | AI Audit | Referensi AI-assisted auditing atau automated vulnerability detection. |

**Catatan**: Semua paper di atas adalah **LIVING REFERENCE** — perlu dibaca dan di-synthesize ke dalam ruleset / training data agent sesuai relevansi teknisnya. Tidak ada yang dipanggil runtime.

---

## 16. Ackee / Trident Ecosystem Resources (Living Reference — Education & Docs)

| # | Resource | Status | Kategori | Peran dalam ARES V3 |
|---|----------|--------|----------|---------------------|
| 63 | **Ackee Solana Handbook** (`Ackee-Blockchain/solana-handbook`) | **REFERENCE** | Education | Buku referensi Solana dari Ackee. Training material untuk agent context Solana. |
| 64 | **Trident API Docs** (`ackee.xyz/trident/docs/latest/trident-api/`) | **REFERENCE** | API Docs | Dokumentasi API Trident. Referensi teknis untuk integrasi Trident CLI. |
| 65 | **Trident Advanced Docs** (`ackee.xyz/trident/docs/latest/trident-advanced/`) | **REFERENCE** | API Docs | Dokumentasi advanced Trident. Referensi untuk custom fuzzing flows dan harness. |
| 66 | **Vibe Fuzzing Guide** (`ackee.xyz/blog/vibe-fuzzing-guide-for-wakes-manually-guided-fuzzing/`) | **REFERENCE** | Blog / Guide | Guide "vibe fuzzing" — manually guided fuzzing workflow. Inspirasi untuk adaptive fuzzing UI di ARES TUI. |
| 67 | **Trident Fuzzing to Solana** (`ackee.xyz/blog/trident-brings-manually-guided-fuzzing-to-solana/`) | **REFERENCE** | Blog / Guide | Blog post awal Trident. Referensi historis dan motivasi produk. |
| 68 | **Trident Arena Blog** (`ackee.xyz/blog/trident-arena-multi-agent-ai-security-for-solana-programs/`) | **REFERENCE** | Blog / Announcement | Announcement Trident Arena dengan benchmark results. Ground truth competitor analysis. |
| 69 | **Ackee Solana Book** (`ackee.xyz/solana/book/latest/`) | **REFERENCE** | Education | Comprehensive Solana book dari Ackee. Training data untuk agent context. |

---

## 17. Security Resources & Audit Guides (Living Reference)

| # | Resource | Status | Kategori | Peran dalam ARES V3 |
|---|----------|--------|----------|---------------------|
| 70 | **Vibranium Audits — How to Audit Solana** (`vibraniumaudits.com/post/how-to-audit-solana-smart-contracts`) | **REFERENCE** | Audit Guide | Guide praktis audit Solana dari Vibranium. Referensi metodologi manual audit yang bisa diotomatisasi. |
| 71 | **Hashlock — How to Become a Smart Contract Auditor** (`hashlock.com/blog/how-to-become-a-smart-contract-auditor-and-get-a-job`) | **REFERENCE** | Career / Education | Guide menjadi auditor. Referensi skillset auditor manusia yang perlu di-emulate agent. |
| 72 | **Hashlock — Smart Contract Audit Cost Calculator** (`hashlock.com/smart-contract-audit-cost-calculator`) | **REFERENCE** | Pricing / Market | Calculator biaya audit. Referensi pricing strategy ARES tiers. |
| 73 | **Zealynx — Solana 2026 Security** (`zealynx.io/blogs/solana-2026-security`) | **REFERENCE** | Market Research | Security landscape Solana 2026. Referensi threat model dan emerging attack vectors. |
| 74 | **Giveth — Auditing in the AI Era** (`giveth.io/project/auditing-in-the-ai-era-open-course`) | **REFERENCE** | Education / Course | Open course auditing di era AI. Referensi curriculum dan learning path untuk ARES agent training. |
| 75 | **SolSec** (`github.com/sannykim/solsec`) | **REFERENCE** | Resource List | Daftar resource keamanan Solana. Referensi comprehensive untuk melengkapi dataset ARES. |
| 76 | **OSWAR** (`oswar.org`) | **REFERENCE** | Security Framework | Open Smart Contract Web Application Security Framework. Referensi taxonomy vulnerability untuk klasifikasi temuan ARES. |
| 77 | **OtterSec — Formally Verifying Solana Programs** (`osec.io/blog/2023-01-26-formally-verifying-solana-programs/`) | **REFERENCE** | Formal Verification | Blog post formal verification Solana. Referensi integrasi Kani / symbolic execution. |

---

## 18. Benchmark & Best Practices (Living Reference)

| # | Resource | Status | Kategori | Peran dalam ARES V3 |
|---|----------|--------|----------|---------------------|
| 78 | **ConsenSys Daedaluzz** (`ConsenSysDiligence/daedaluzz`) | **REFERENCE** | Fuzzer Benchmark | Benchmark fuzzer untuk EVM smart contracts. Referensi metodologi benchmark yang bisa diadaptasi ke Solana. |
| 79 | **ConsenSys Smart Contract Best Practices** (`ConsenSysDiligence/smart-contract-best-practices`) | **REFERENCE** | Best Practices | Best practices Solidity/EVM. Referensi pola secure coding yang bisa di-translate ke Rust/Anchor. |
| 80 | **MetaDAO Programs Fuzzing** (`Ackee-Blockchain/metadao-programs-fuzzing`) | **REFERENCE** | Fuzzing Example | Contoh fuzzing program MetaDAO dengan Trident. Referensi harness structure dan test pattern. |
| 81 | **Ackee Public Audit Reports** (`Ackee-Blockchain/public-audit-reports`) | **REFERENCE** | Audit Dataset | Laporan audit publik Ackee. Training data untuk Reporter Agent dan ground truth benchmark. |
| 82 | **Trident IDL Spec** (`Ackee-Blockchain/trident-idl-spec`) | **REFERENCE** | Spec / Standard | Spesifikasi IDL kustom Trident. Referensi teknis untuk IDL parsing. |
| 83 | **Cascade SATI** (`cascade-protocol/sati`) | **REFERENCE** | Protocol / Tool | Tool dari Cascade Protocol. Perlu riset lebih lanjut untuk relevansi spesifik. |
| 84 | **Anchor Optional Bug** (`exo-tech-xyz/anchor-1-0-0-rc-2-optional-bug`) | **REFERENCE** | Bug Example | Contoh bug spesifik di Anchor. Training data untuk pattern recognition. |

---

## 19. Provos / Zero-Day Research (Living Reference)

| # | Resource | Status | Kategori | Peran dalam ARES V3 |
|---|----------|--------|----------|---------------------|
| 85 | **Finding Zero Days with Any Model** (`provos.org/p/finding-zero-days-with-any-model/`) | **REFERENCE** | Research Blog | Blog post Niels Provos tentang zero-day discovery dengan model apapun. Referensi metodologi zero-day hunting yang bisa diadaptasi ke Solana. |
| 86 | **IronCurtain (GitHub)** (`github.com/provos/ironcurtain`) | **REFERENCE** | Policy Engine | Repo open-source IronCurtain. Referensi implementasi policy engine dan capability escalation. |

---

## 20. Payment & Monetization References (Living Reference)

| # | Resource | Status | Kategori | Peran dalam ARES V3 |
|---|----------|--------|----------|---------------------|
| 87 | **MPP.dev LLMs** (`mpp.dev/llms.txt`) | **REFERENCE** | LLM Context | Dokumentasi MPP.dev dalam format LLM-friendly. Referensi untuk payment gateway integration. |
| 88 | **Tempo / MPP.dev Guides** (pay-as-you-go, streamed-payments, payment-links, proxy-existing-service, upgrade-x402) | **REFERENCE** | Payment Gateway | Berbagai guide pembayaran crypto (Tempo, Stripe, Lightning). Referensi untuk tier ARES Enterprise/API monetization. |

---

## 21. UI/UX & Design References (Living Reference)

| # | Resource | Status | Kategori | Peran dalam ARES V3 |
|---|----------|--------|----------|---------------------|
| 89 | **Ampcode** (`ampcode.com`) | **REFERENCE** | UI/UX Reference | Referensi UI/UX untuk web app ARES (visual style, layout, interaction patterns). |
| 90 | **Color Hunt Palettes** (5 palet di `Resources.md`) | **REFERENCE** | Design Token | Palet warna untuk branding dan UI ARES. |

---

## 22. Video & Content Generation (Living Reference — Tier Enterprise/Optional)

| # | Resource | Status | Kategori | Peran dalam ARES V3 |
|---|----------|--------|----------|---------------------|
| 91 | **Remotion** (`remotion-dev/remotion`, `remotion-dev/skills`, `remotion-dev/html-in-canvas`) | **REFERENCE** | Video Generation | Framework video programmatic dengan React. Referensi untuk generate video tutorial / demo ARES otomatis. |
| 92 | **create-video@latest** | **REFERENCE** | Video Scaffolding | Scaffolding project video. Referensi quick-start content generation. |

---

## Ringkasan Total (Updated)

| Kategori | Jumlah | Daftar Singkat |
|----------|--------|----------------|
| **INTEGRATED (Core)** | 6 | Trident, Trident SVM, Solana CLI, Anchor CLI, SPL, cargo-audit |
| **PLANNED (Phase 2–3)** | 6 | Kani, cargo-geiger, test-fuzz, necessist, IDLGuesser, OpenRouter SDK |
| **OPTIONAL (Enterprise/Advanced)** | 2 | sec3 X-Ray, otter-verify integration |
| **REFERENCE (Architecture/Benchmark/Patterns/Education)** | **74+** | CBMC, dylint, sol-ctf-framework, solana-poc-framework, checked-math, vipers, IronCurtain, Kubescape, Trident Arena, SCONE-bench, Opus 4.6, Foundry, agent skills (ToB, QEDGen, zz-code-recon, vulnhunter, vercel, google-labs), anchor-UI, auditor-template, mpp.dev, Stripe, Claude Code, OpenCode, OpenTUI, 12 arxiv papers, Ackee ecosystem docs, Vibranium, Hashlock, Zealynx, Giveth, SolSec, OSWAR, OtterSec blog, Daedaluzz, best practices, Provos zero-day, 5 color palettes, Ampcode, Remotion, dll. |
| **LIVING** | ~30+ | Semua link Google Docs, arxiv, blog post, color palette, skill libs yang sering update. |

---

## Diagram Alur Integrasi Runtime (INTEGRATED + PLANNED)

```
┌─────────────────────────────────────────────────────────────┐
│  ARES V3 CLI / Agent Orchestrator                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Mapper Agent                                               │
│  ├──> cargo-audit (dep CVE scan)                            │
│  ├──> cargo-geiger (unsafe Rust scan)  [PLANNED]           │
│  ├──> rust-analyzer / cargo check (AST + type inference)   │
│  ├──> IDLGuesser / Anchor IDL parse        [PLANNED]       │
│  └──> Git history analysis (bash + git CLI)                │
│                                                             │
│  Hypothesis Generator Agent                                 │
│  ├──> Rules Engine (custom, terinspirasi dylint/vipers)    │
│  └──> CVE/CWE dataset lookup                               │
│                                                             │
│  Fuzzer Orchestrator Agent                                  │
│  ├──> Trident CLI (`trident fuzz run`)                     │
│  ├──> Trident SVM (embedded execution)                     │
│  ├──> Kani (`cargo kani`)                  [PLANNED]       │
│  └──> Solana test validator (fork mainnet) [PLANNED]     │
│                                                             │
│  Exploit Constructor Agent                                  │
│  ├──> Anchor test generator (`anchor test` compatible)       │
│  ├──> test-fuzz harness generator          [PLANNED]       │
│  └──> PoC Rust/TS test output                              │
│                                                             │
│  Triager Agent                                              │
│  ├──> Run PoC di sandbox Docker                             │
│  └──> necessist mutation test              [PLANNED]       │
│                                                             │
│  Reporter Agent                                             │
│  ├──> GitHub Issue / PR generation                         │
│  ├──> PDF / Markdown report                                 │
│  └──> CI workflow template (`ares-security.yml`)          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Catatan Penting

1. **Semua tool REFERENCE tidak akan di-bundle dalam binary/runtime ARES V3**. Mereka ada di dokumentasi arsitektur untuk tim engineer memahami "best practice" yang harus diimplementasi ulang atau diadaptasi ke domain Solana/Rust.

2. **Tool INTEGRATED dipanggil via CLI wrapper atau MCP server**, bukan di-embed sebagai library (kecuali Trident SVM yang memang Rust library). Ini mengikuti prinsip Unix philosophy dan memudahkan sandboxing.

3. **Tool PLANNED memerlukan prioritisasi** berdasarkan hasil benchmark Phase 1. Jika Trident fuzzing saja sudah mencapai >80% detection, Kani dan formal verification bisa ditunda ke Phase 4.

4. **Solana-equivalent toolchain** dibandingkan dengan SCONE-bench EVM:

| EVM (SCONE-bench) | Solana (ARES V3) |
|-------------------|-------------------|
| `anvil` (local EVM) | `solana-test-validator` |
| `forge` (build/test) | `anchor test` + `trident fuzz run` |
| `cast` (interact) | `solana` CLI + custom TS/Rust scripts |
| Foundry framework | Trident framework |
| Ethers.js / web3.js | `@solana/web3.js` + Anchor client |

