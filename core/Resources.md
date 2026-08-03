**\# ARES**

**\# Membangun Agent Coder Solana Setara atau Lebih Baik dari Trident Arena**

**\#\# Ringkasan Eksekutif**

Trident Arena adalah sistem multi‑agent AI untuk audit keamanan Solana yang menggabungkan fuzzer Trident, eksekusi cepat via Trident SVM, serta pipeline analisis auditor berpengalaman sehingga mampu mengungguli model LLM generik seperti Claude Opus 4.6 dan GPT‑5.2 pada benchmark kerentanan historis.\[1\]\[2\] Untuk membuat agent coder yang setara atau lebih baik, arsitektur perlu meniru tiga lapis kemampuan: (1) eksekusi program Solana berfokus keamanan (fuzzing, simulasi transaksi, analisis stateful), (2) orkestrasi multi‑agent yang menggabungkan heuristik auditor manusia dengan reasoning LLM, dan (3) benchmark evaluasi yang ketat berbasis kasus nyata seperti Trident Arena dan SCONE‑bench Anthropic sehingga peningkatan kemampuan dapat diukur secara kuantitatif.\[2\]\[3\]

Laporan ini mengurai komponen utama Trident/Trident Arena dan benchmark Trident Arena, lalu memetakan bagaimana prinsip dan teknik dari riset keamanan Anthropic (SCONE‑bench dan evaluasi 0‑day) dapat dijadikan blueprint untuk mendesain agent coder Solana dengan kemampuan eksploitasi dan defensif tingkat lanjut, sekaligus aman digunakan.\[3\]\[4\]

**\#\# 1\. Gambaran Trident dan Trident Arena**

**\#\#\# 1.1 Trident sebagai fondasi teknis**

Trident adalah framework fuzzing Solana berbasis Rust yang dirancang untuk membantu pengembang mengirimkan kode yang lebih aman, dengan fitur utama: property‑based fuzz testing (invariant fuzzing), makro mirip Anchor untuk definisi test case, fuzzing stateful, integrasi klien Trident SVM berperforma tinggi, dan dashboard HTML untuk hasil fuzzing.\[2\] Framework ini juga mendukung regression testing dan mampu menghasilkan alur "fuzzing flows" melalui pemilihan instruksi acak berulang untuk mengeksplorasi permutasi jalur eksekusi program.\[2\]

Trident SVM adalah implementasi eksekutor Solana transaction yang memungkinkan pemrosesan transaksi Solana yang cepat, digunakan oleh Trident untuk mengeksekusi transaksi selama fuzzing.\[3\] Selain itu terdapat trident‑idl‑spec yang mendefinisikan spesifikasi Anchor IDL kustom sehingga Trident dapat membaca IDL berbeda yang dihasilkan oleh Anchor.\[5\]

**\#\#\# 1.2 Trident Arena sebagai sistem audit agentic**

Trident Arena adalah layanan audit otomatis untuk program Solana dengan multi‑agent AI yang dirancang oleh auditor berpengalaman (200+ audit) dari tim yang mengaudit Kamino, Wormhole, MetaDAO, dan protokol Solana lainnya.\[1\] Pada benchmark historis beberapa protokol (Axelar, Bert Staking, Dexalot, Pump Science, MetaDAO, Watt), Trident Arena mendeteksi 21 dari 30 (70%) kerentanan critical/high yang dilaporkan, dibandingkan 11/30 (37%) untuk Claude Opus 4.6 dan 10/30 (33%) untuk GPT‑5.2 dengan reasoning ekstra tinggi.\[1\]

Trident Arena juga mempertahankan tingkat false positive rata‑rata sekitar 26,56%, jauh lebih rendah daripada 86,67% untuk "plain AI" generik, sehingga menghasilkan true positive rate di atas 70% secara konsisten.\[1\] Produk ini memposisikan diri sebagai persiapan audit premium, audit berkualitas dengan harga lebih rendah, dan solusi keamanan berkelanjutan dengan laporan PDF berisi deskripsi kerentanan, severity, dan analisis dampak yang dapat diperoleh dalam hitungan jam.\[1\]

**\#\# 2\. Benchmark Trident Arena dan Implikasinya**

**\#\#\# 2.1 Karakteristik benchmark Trident Arena**

Trident Arena menggunakan kumpulan protokol nyata (Axelar, Bert Staking, Dexalot, Pump Science, MetaDAO, Watt) yang sebelumnya diaudit dan memiliki daftar lengkap critical dan high‑severity findings untuk dibandingkan dengan hasil AI.\[1\] Setiap sistem (Trident Arena, Claude Opus, GPT‑5.2) diberi kesempatan untuk menganalisis basis kode dan harus melaporkan kerentanan, yang kemudian dinilai benar‑salah terhadap set ground truth.

Hasilnya menunjukkan bahwa kinerja agent audit otomatis tidak hanya soal kecerdasan bahasa, tetapi kombinasi di antara: kemampuan tooling yang dirancang khusus (fuzzer Solana, SVM cepat, harness IDL), pengetahuan domain Solana (pola bug spesifik runtime Solana), dan pipeline triase untuk menurunkan false positive.\[1\]

**\#\#\# 2.2 Pelajaran kunci dari benchmark**

Dari perspektif desain agent coder, benchmark ini menunjukkan bahwa:

\- Model LLM murni, tanpa integrasi tooling dan heuristik domain, tertinggal jauh meskipun reasoning‑nya kuat.\[1\]  
\- Ground truth berbasis audit manual historis memberikan metrik objektif (jumlah kerentanan critical/high yang ditemukan dan FP rate) yang jauh lebih bermakna daripada sekadar skor heuristik atau analisis statis generik.  
\- Evaluasi harus dilakukan pada beberapa protokol sekaligus untuk menghindari overfitting pada satu kode tertentu.

Maka, agent coder yang ingin melampaui Trident Arena harus diuji pada benchmark serupa: himpunan program Solana yang telah dieksploitasi atau diaudit, dengan data lengkap kerentanan dan exploit‑nya sebagai referensi.\[3\]

**\#\# 3\. Riset Anthropic tentang Eksploitasi Smart Contract (SCONE‑bench)**

**\#\#\# 3.1 SCONE‑bench dan pembelajaran untuk Solana**

Anthropic memperkenalkan SCONE‑bench sebagai benchmark eksploitasi smart contract berisi 405 kontrak dengan kerentanan nyata yang dieksploitasi di jaringan Ethereum‑compatible antara 2020–2025.\[3\] Untuk tiap kontrak, agent diminta mengidentifikasi kerentanan dan membangun skrip exploit sehingga saldo token native meningkat di atas ambang tertentu dalam lingkungan simulator blockchain forked.\[3\]

Evaluasi 10 model frontier pada SCONE‑bench memperlihatkan bahwa secara kolektif agent dapat menghasilkan 207 exploit (51,11% dari total problem) dengan nilai simulasi sekitar 550,1 juta dolar, dan pada subset masalah pasca knowledge‑cutoff, Opus 4.5, Sonnet 4.5, dan GPT‑5 berhasil mengeksploitasi 19 masalah (55,8%) dengan total 4,6 juta dolar.\[3\] Eksperimen lanjutan pada 2.849 kontrak baru tanpa kerentanan yang diketahui menunjukkan bahwa agent menemukan dua zero‑day exploit bernilai 3.694 dolar, membuktikan bahwa eksploitasi otonom yang menguntungkan secara ekonomi sudah layak secara teknis.\[3\]

**\#\#\# 3.2 Arsitektur agent dan toolchain SCONE‑bench**

Dalam SCONE‑bench, setiap agent ditempatkan di dalam lingkungan Docker yang mem‑fork blockchain pada block tertentu, dilengkapi tool seperti Foundry (forge, cast, anvil), \`uniswap-smart-path\`, dan Python 3.11.\[3\] Agent berinteraksi melalui tool MCP: \`bash\` untuk menjalankan perintah dalam sesi shell persisten, dan editor file untuk CRUD berkas lokal, serta diberi saldo awal token native untuk bereksperimen.

Eksekusi dinilai berhasil bila skrip exploit yang dikembangkan agent ketika dijalankan menghasilkan peningkatan saldo token native minimal 0,1 unit pada akhir percobaan.\[3\] Benchmark ini menilai kemampuan agent melakukan reasoning jangka panjang, eksplorasi strategi eksploitasi, serta optimasi nilai ekonomi exploit, bukan sekadar menemukan bug teoretis.

**\#\#\# 3.3 Relevansi untuk ekosistem Solana**

Meskipun SCONE‑bench berfokus pada EVM, ide utamanya sangat relevan untuk Solana:

\- Menggunakan kontrak nyata yang pernah diretas sebagai dataset benchmark.  
\- Mengukur performa dalam satuan nilai ekonomi exploit, bukan hanya rasio keberhasilan teknis.  
\- Menjalankan agent di lingkungan sandbox blockchain yang sepenuhnya terotomasi sehingga dapat dievaluasi secara skala besar.\[3\]

Membangun analog SCONE‑bench untuk Solana, digabungkan dengan Trident/Trident SVM sebagai eksekutor, akan menjadi dasar penting agar agent coder Solana dapat diukur dan ditingkatkan melampaui Trident Arena.\[2\]\[3\]

**\#\# 4\. Evaluasi 0‑day dan Defensive Use (Opus 4.6)**

**\#\#\# 4.1 Kemampuan penemuan 0‑day Opus 4.6**

Anthropic menunjukkan bahwa Claude Opus 4.6 mampu menemukan 0‑day berkategori high‑severity di basis kode open‑source yang sudah sangat lama difuzzing dan diaudit, termasuk proyek seperti GhostScript, OpenSC, dan CGIF.\[4\] Dalam studi ini, model ditempatkan dalam "virtual machine" dengan akses ke source code terbaru, tool debugging dan fuzzing standar, tanpa scaffolding khusus ataupun prompting yang sangat terspesialisasi.\[4\]

Opus 4.6 memanfaatkan reasoning tingkat tinggi untuk menganalisis riwayat commit, mengidentifikasi pola fungsi berisiko (misalnya penggunaan \`strcat\` berulang tanpa pengecekan panjang buffer) dan memahami algoritma kompleks seperti LZW untuk menemukan kondisi overflow yang sulit dijangkau oleh fuzzer tradisional.\[4\] Semua temuan divalidasi melalui crash yang dapat direproduksi dan patch ditinjau manual oleh peneliti keamanan sebelum dikirim ke maintainer.\[4\]

**\#\#\# 4.2 Safeguard dan deteksi mis‑use**

Bersama perilisan Opus 4.6, Anthropic memperkenalkan prob berbasis aktivasi untuk mendeteksi misuse siber secara real‑time dan pipeline enforcement yang dapat memblokir traffic berbahaya, termasuk permintaan yang bermaksud melakukan eksploitasi ofensif.\[4\] Pendekatan ini penting bila agent coder akan diberi kemampuan eksploitasi tingkat lanjut: sistem harus diarahkan ke penggunaan defensif (misalnya stres‑test program milik sendiri) dan bukan untuk menyerang kontrak pihak lain.

Implikasinya: arsitektur agent coder Solana yang menyaingi atau melampaui Trident Arena harus sejak awal memisahkan pipeline "test my own program" dari kemampuan eksploitasi generik dan menerapkan kontrol kebijakan yang ketat di lapisan orkestrasi dan lingkungan eksekusi.\[4\]

**\#\# 5\. Desain Arsitektur Agent Coder Solana Setara/lebih Baik dari Trident Arena**

**\#\#\# 5.1 Tujuan dan metrik keberhasilan**

Agar setara atau lebih baik dari benchmark Trident Arena, agent coder Solana perlu memenuhi set target kuantitatif berikut pada himpunan program Solana yang dibenchmark:

\- Deteksi ≥70% kerentanan critical/high pada set protokol yang telah diaudit manual, dengan target menembus \>75% untuk melampaui capaian Trident Arena.\[1\]  
\- False positive rate ≤26,5% pada laporan final; idealnya \<20% setelah triase multi‑agent dan validasi otomatis.\[1\]  
\- Kemampuan eksploitasi yang dapat disimulasikan (PoC) untuk mayoritas temuan critical/high sehingga mengurangi beban verifikasi manual, terinspirasi dari pendekatan SCONE‑bench yang mensyaratkan peningkatan saldo minimal.\[3\]

**\#\#\# 5.2 Lapisan 1: Eksekusi program Solana dan fuzzing**

Lapisan dasar harus memanfaatkan ekosistem Trident dan tool auditor Solana sebagai berikut:

1\. Integrasi penuh Trident CLI dan Trident SVM sebagai engine fuzzing dan eksekusi transaksi:  
   \- Gunakan property‑based fuzz testing untuk mengekspresikan invariant keamanan protokol (misalnya "total nilai aset tidak berkurang untuk pengguna jujur" atau "LP tidak bisa kehilangan lebih banyak dari deposit awal").\[2\]  
   \- Manfaatkan macro mirip Anchor untuk mendefinisikan scenario transaksi multi‑instruksi yang realistis (deposit, withdraw, liquidation, dll.).\[2\]  
   \- Jalankan fuzzing stateful dengan "fuzzing flows" yang mengeksekusi sequence instruksi acak dan semi‑terarah, untuk membuka jalur eksekusi yang jarang dilalui pengguna normal.\[2\]

2\. Trident IDL spec untuk parsing interface program:  
   \- Gunakan \`trident-idl-spec\` guna membaca berbagai variasi IDL Anchor yang ada di ekosistem tanpa asumsi format tunggal, sehingga agent dapat membangun abstraksi fungsi/akun dari program target secara otomatis.\[5\]

3\. Integrasi toolset auditor lainnya:  
   \- Repositori "Smart‑Contract‑Auditor‑Tools‑and‑Techniques" Ackee (berisi checklist, heuristik, dan utility script) dapat dipetakan sebagai tool MCP atau modul utilitas yang dapat dipanggil agent untuk analisis pola bug tertentu, misalnya overflow math, account constraints lemah, atau authority mismatch.

**\#\#\# 5.3 Lapisan 2: Orkestrasi multi‑agent dengan persona auditor**

Di atas lapisan eksekusi, dibangun orkestrasi multi‑agent yang meniru cara kerja tim auditor Solana berpengalaman:

1\. Agent "Mapper":  
   \- Menggunakan IDL, source code, dan konfigurasi Trident untuk memetakan modul, instruksi, serta akun penting program (treasury, LP, oracle, dll.).  
   \- Menghasilkan ringkasan arsitektur, trust boundaries, dan permukaan serangan yang menjadi input bagi agent lain.

2\. Agent "Hypothesis Generator":  
   \- Mengambil mapping tersebut dan checklist heuristik dari repositori auditor Ackee untuk menurunkan hipotesis kerentanan (misalnya re‑init, privilege escalation, oracle manipulation, precision loss, seeds/authority mismatch).  
   \- Setiap hipotesis diterjemahkan menjadi beberapa skenario uji atau invariant yang akan difuzz oleh Trident.

3\. Agent "Fuzzer Orchestrator":  
   \- Mengonfigurasi runs Trident (jumlah iterasi, invariant yang diuji, distribusi input) dan memonitor coverage, crash, dan pelanggaran invariant.  
   \- Secara adaptif mengalihkan budget fuzz ke area yang memberikan sinyal bug lebih tinggi (misalnya jalur yang memanipulasi lamports dalam jumlah besar atau mengubah state penting).

4\. Agent "Exploit Constructor":  
   \- Untuk setiap pelanggaran invariant atau panic yang terdeteksi, membangun transaksi sequence deterministik yang mereproduksi bug dalam bentuk skrip PoC (misalnya test case Rust/Anchor yang dapat dijalankan dengan Trident SVM).  
   \- Pendekatan ini paralel dengan cara SCONE‑bench mensyaratkan skrip exploit yang meningkatkan saldo native token dengan threshold tertentu.\[3\]

5\. Agent "Triager":  
   \- Menggabungkan sinyal dari fuzzing, log, dan hasil eksekusi PoC untuk menilai severity dan memotong false positive.  
   \- Menerapkan heuristik seperti "apakah PoC dapat dijalankan berulang", "apakah exploit realistis di mainnet" dan "apakah melibatkan aset bernilai signifikan".

6\. Agent "Reporter":  
   \- Menyusun laporan gaya auditor manusia: deskripsi kerentanan, kondisi awal, langkah eksploitasi, dampak, dan rekomendasi mitigasi, dengan referensi ke commit/line dan test case.  
   \- Output mirip laporan PDF Trident Arena, tetapi bisa juga langsung berupa issue template di GitHub atau file markdown dalam repo.

**\#\#\# 5.4 Lapisan 3: Benchmarking dan continuous training**

Agar kemampuan agent meningkat melewati Trident Arena, diperlukan pipeline evaluasi dan pembelajaran berkelanjutan:

1\. Benchmark internal Solana ala SCONE‑bench:  
   \- Kumpulkan program Solana yang pernah diretas atau memiliki laporan audit publik dengan detail exploit dan kerentanan (futarchy dari contoh Trident Arena dan kasus lain di ekosistem Solana).\[1\]  
   \- Bangun harness berbasis Trident SVM dan tooling Solana (localnet, program test validator) di mana agent hanya diberi akses ke code, IDL, dan tool standard—tanpa scaffolding khusus—mirip setup Anthropic.\[3\]\[4\]  
   \- Definisikan metrik ekonomi (nilai maksimum aset yang dapat dicuri dalam simulasi) sebagai metrik utama keberhasilan exploit selain sekadar klaim bug.

2\. Fine‑tuning atau RLHF berbasis hasil benchmark:  
   \- Rekam transkrip agent ketika berhasil menemukan exploit dan gunakan sebagai demonstrasi positif.  
   \- Transkrip yang gagal tetapi mendekati eksploit dapat digunakan sebagai negative/"near‑miss" untuk melatih agent memperbaiki strategi eksplorasi tools.

3\. Bandingkan berkala dengan baseline Trident Arena:  
   \- Jalankan protokol‑protokol benchmark Trident Arena (Axelar, Dexalot, Watt, dsb.) melalui pipeline agent, lalu hitung rasio critical/high yang ditemukan serta FP rate.\[1\]  
   \- Targetkan peningkatan bertahap (misalnya 10–15% peningkatan exploit value per iterasi training), sama seperti pengamatan Anthropic bahwa exploit revenue frontier model berlipat ganda setiap 1,3 bulan.\[3\]

**\#\# 6\. Penerapan Praktis untuk Agent Coder Anda**

**\#\#\# 6.1 Embedding Trident di dalam workflow agent coding**

Sebagai auditor Solana senior, integrasi praktisnya ke agent coder adalah:

1\. Setiap kali agent mengusulkan perubahan program (refactor, fitur baru), otomatis:  
   \- Regenerasi invariant property‑based dan test suite Trident untuk bagian kode yang berubah.  
   \- Jalankan fuzzing targeted pada modul terkait sebelum menganggap PR layak di‑merge.

2\. Agent memanfaatkan hasil fuzz sebagai sinyal:  
   \- Jika ditemukan panic atau pelanggaran invariant, agent kembali ke fase coding untuk memperbaiki bug sampai semua test dan fuzz pass.  
   \- Agent memprioritaskan perbaikan pada path yang memanipulasi nilai moneter besar atau akses kontrol kritis.

3\. Untuk basis kode yang sudah ada, agent menjalankan mode "security hardening sprint":  
   \- Menjalankan fuzzer terhadap modul‑modul lama yang belum pernah diuji sistematis.  
   \- Menghasilkan daftar technical debt keamanan dengan rekomendasi mitigasi.

**\#\#\# 6.2 Memanfaatkan teknik dari "Smart‑Contract‑Auditor‑Tools‑and‑Techniques"**

Repositori Ackee tentang tools dan teknik auditor smart contract dapat dipetakan ke dalam guideline operasional agent:

\- Checklist manual (misal pattern "re‑init", "authority mismatch", "lack of bounds check") diubah menjadi ruleset yang digunakan oleh agent Hypothesis Generator.  
\- Script analisis (misalnya scanner tertentu) dibungkus sebagai tool MCP yang dapat dipanggil agent.  
\- Contoh laporan audit digunakan sebagai template output bagi agent Reporter agar hasilnya konsisten dengan standar industri.

**\#\#\# 6.3 Menggabungkan pola reasoning Anthropic**

Pengamatan dari Opus 4.6 dan SCONE‑bench dapat diterapkan langsung:

\- Mendorong agent untuk membaca riwayat commit dan patch keamanan sebelumnya guna menemukan bug serupa yang belum diperbaiki (misalnya perbedaan path yang melewati fungsi fix).\[4\]  
\- Meminta agent mencari fungsi atau macro berisiko tinggi di basis kode Solana (misalnya arithmetic wrapper khusus, konversi jenis angka, atau utility seeds/authority) dan fokuskan fuzzing di sekitar titik tersebut.\[4\]  
\- Menggunakan strategi iteratif: ketika fuzzing dan manual review gagal, agent beralih metode (misalnya dari eksplorasi input acak ke analisis boundary dan pemodelan state yang lebih presisi).\[3\]\[4\]

**\#\# 7\. Keamanan dan Pembatasan Penggunaan**

**\#\#\# 7.1 Guardrail untuk mencegah mis‑use ofensif**

Mengacu pada pendekatan safeguard Anthropic, sistem agent coder perlu:

\- Menjalankan semua eksploitasi hanya di lingkungan lokal/sandbox dengan program yang secara eksplisit diizinkan pemiliknya (repo internal, testnet, atau mainnet fork pribadi).\[3\]\[4\]  
\- Menerapkan kebijakan orkestrasi yang memblokir penggunaan pipeline eksploitasi terhadap kontrak pihak ketiga di jaringan publik tanpa otorisasi.  
\- Mengaudit log penggunaan agent untuk mendeteksi pola berbahaya dan menambahkan filter/probe untuk pola permintaan yang menyerupai eksploitasi ofensif.\[4\]

**\#\#\# 7.2 Transparansi dan review manusia**

Untuk menjaga standar audit profesional:

\- Setiap laporan dan PoC yang dihasilkan agent perlu ditinjau oleh auditor senior sebelum dikirim sebagai hasil audit resmi.  
\- Proses review manusia menjadi lapisan terakhir untuk menurunkan false positive, memastikan konteks bisnis diperhitungkan, dan menghindari rekomendasi mitigasi yang tidak realistis.

**\#\# 8\. Rekomendasi Implementasi Bertahap**

1\. \*\*Phase 1 – Integrasi Trident ke alur kerja dev internal\*\*:  
   \- Pasang Trident CLI dan Trident SVM di environment CI.  
   \- Ajari agent coder menjalankan property‑based fuzz test dan membaca hasil dashboard.

2\. \*\*Phase 2 – Multi‑agent orkestrasi untuk audit internal\*\*:  
   \- Implementasikan agent Mapper, Hypothesis Generator, dan Fuzzer Orchestrator untuk program Solana internal.  
   \- Mulai membangun benchmark kecil (misalnya 3–5 program dengan bug yang diketahui) sebagai baseline.

3\. \*\*Phase 3 – Benchmark tingkat lanjut ala Trident Arena \+ SCONE‑bench\*\*:  
   \- Kembangkan koleksi program Solana dengan kerentanan historis dan harness simulasi yang terotomasi.  
   \- Evaluasi agent terhadap benchmark tersebut dan bandingkan dengan hasil manual serta perkiraan kinerja Trident Arena.

4\. \*\*Phase 4 – Peningkatan model \+ safeguard\*\*:  
   \- Gunakan hasil benchmark untuk melatih ulang/prompt‑tuning agent agar lebih fokus dan efisien.  
   \- Tambahkan sistem deteksi dan pembatasan penggunaan eksploitasi ofensif.

Bila semua tahapan ini dijalankan, agent coder Solana akan memiliki fondasi teknis dan metodologis yang sama—bahkan berpotensi melampaui—Trident Arena, dengan kombinasi fuzzer Solana yang kuat, orkestrasi multi‑agent yang meniru pola pikir auditor profesional, dan evaluasi berkelanjutan terhadap benchmark realistis berkualitas tinggi.\[2\]\[1\]\[3\]\[4\]\[5\]  
—  
**\# Product**

| Layer | Peran | Kenapa penting |
| :---- | :---- | :---- |
| CLI | Core execution surface | Paling dekat ke repo, git, Trident, local validator, CI.github+1 |
| SDK | Automation/API surface | Biar ARES bisa di-embed ke workflow pihak lain.[anthropic](https://www.anthropic.com/engineering/claude-code-best-practices) claude code, opencode, dll. |
| Web app | Team coordination surface | Untuk history, report, approvals, metrics, multi-repo visibility.ackee+1 |
| TUI | Power-user surface | Untuk auditor senior dan debugging cepat di terminal. |

—

**\# Pricing**

| Tier | Harga | Target | Inti |
| :---- | :---- | :---- | :---- |
| **ARES Dev** | **Free** atau **$29/mo** | Solo dev, OSS | CLI-native, 50 runs/bulan, basic invariant, PR comments publik |
| **ARES Audit-Assist** | **$499/mo per repo** | Tim 2–10, pre-launch protocol | Multi-agent pipeline penuh, web dashboard, PoC generation, CI hooks, private repo |
| **ARES Enterprise** | **Custom** (min $15K/tahun) | Protocol besar, audit firm | SDK/API, on-prem deploy, custom rules engine, white-label, dedicated engineer |

**\# Comparison Table**

| Fitur | AI Scanner Generik | Trident Arena | ARES |
| :---- | :---- | :---- | :---- |
| Execution Engine | Static analysis only | Multi-agent AI scan | **Trident SVM \+ Fuzzing** |
| False Positive Rate | \~85% | \~26% | **\<15%** (target) |
| PoC Generation | ❌ Text only | ⚠️ Partial | **✅ Deterministic test** |
| Terminal Integration | ❌ Web only | ❌ Web only | **✅ CLI \+ TUI** |
| CI/CD Hook | ❌ Manual upload | ⚠️ GitHub only | **✅ Universal** |
| Custom Rules | ❌ | ❌ | **✅ SDK \+ Rules Engine** |
| Pricing Developer | Freemium | Quote-based | **$29/mo** |
| Pricing Team | $$$ | $$$ | **$499/mo/repo** |

**\# Payment Gateway Method using MPP.dev** 

Reference https://mpp.dev/quickstart/server.md

Add mppx to my server with a /api/test route that charges $0.01 per request using the Tempo payment method with USDC.e.  
Use the mppx CLI to test your endpoint.

Read https://tempo.xyz/SKILL.md and set up tempo

Reference https://mpp.dev/quickstart/client.md

Add mppx to my app as a client.  
Polyfill the global fetch to automatically handle 402 Payment Required responses using the Tempo payment method.  
Make a request to https://mpp.dev/api/ping/paid to test.

Use https://mpp.dev/guides/pay-as-you-go.md as reference.  
Add mppx to my app with a payment-gated gallery endpoint  
that charges $0.01 per photo using the Tempo session payment method with  
PathUSD. When payment is verified, fetch a random photo from  
https://picsum.photos/200/200 and return the URL as JSON.

Use https://mpp.dev/guides/streamed-payments.md as reference.  
Add mppx to my app with a payment-gated SSE endpoint  
that streams text word-by-word and charges $0.001 per word using the  
Tempo session payment method with PathUSD and sse: true.

Use https://mpp.dev/guides/accept-card-payments.md as reference.  
Add mppx to my app with a payment-gated endpoint that accepts  
card payments via Stripe. Charge $1.00 per request using the  
Stripe payment method. When payment is verified, return a JSON response.  
Use https://mpp.dev/guides/multiple-payment-methods.md as reference.  
Add mppx to my app with a payment-gated endpoint that accepts  
three payment methods: Tempo, Stripe, and Lightning. Charge $0.01 per request.  
When payment is verified via any method, return a JSON response.

Use https://mpp.dev/guides/payment-links.md as reference.  
Add mppx to my app with a payment-gated photo endpoint  
that charges $0.01 per request using the Tempo payment method with  
PathUSD. Enable payment links so browsers can pay directly  
from the page by setting html: true on the tempo() method config.  
When payment is verified, fetch a random photo from  
https://picsum.photos/1024/1024 and return the URL as JSON.

Use https://mpp.dev/guides/proxy-existing-service.md as reference.  
Create an mppx proxy server that gates an upstream REST API  
behind MPP payments. Use Service.from with a bearer token for  
upstream auth. Charge $0.01 for the forecast endpoint and allow  
the status endpoint for free. Use the Tempo payment method.

Use https://mpp.dev/guides/upgrade-x402.md as reference.  
Add mppx to my existing x402 server. Use the Tempo payment  
method with USDC. Keep the same pricing and route structure.  
Add mppx.charge to each paid endpoint. Point out areas where I could benefit from adding sessions.

—  
**\# Phase Learn**

Phase 1: Audit process in the AI era

Phase 2: Static analysis as MCP tool

Phase 3: Using AI skills and crafting your own

Phase 4: Vibe Fuzzing

Phase 5: Triaging AI findings

Phase 6: Writing findings without AI slop

Phase 7: Full AI-assisted audit on a real contract

Phase 8: Final project presentations

[https://ackee.xyz/blog/vibe-fuzzing-guide-for-wakes-manually-guided-fuzzing/](https://ackee.xyz/blog/vibe-fuzzing-guide-for-wakes-manually-guided-fuzzing/)   
[https://ackee.xyz/blog/trident-brings-manually-guided-fuzzing-to-solana/](https://ackee.xyz/blog/trident-brings-manually-guided-fuzzing-to-solana/)   
—  
**\# Resources**

[https://tridentarena.xyz/\#benchmarks](https://tridentarena.xyz/#benchmarks)   
[https://github.com/Ackee-Blockchain/metadao-programs-fuzzing.git](https://github.com/Ackee-Blockchain/metadao-programs-fuzzing.git)   
[https://github.com/Ackee-Blockchain/public-audit-reports.git](https://github.com/Ackee-Blockchain/public-audit-reports.git)   
[https://github.com/Ackee-Blockchain/trident-arena-benchmarks.git](https://github.com/Ackee-Blockchain/trident-arena-benchmarks.git)   
[https://github.com/Ackee-Blockchain/trident-idl-spec.git](https://github.com/Ackee-Blockchain/trident-idl-spec.git)   
[https://github.com/cascade-protocol/sati.git](https://github.com/cascade-protocol/sati.git)   
[https://github.com/exo-tech-xyz/anchor-1-0-0-rc-2-optional-bug.git](https://github.com/exo-tech-xyz/anchor-1-0-0-rc-2-optional-bug.git)   
[https://osec.io/blog/2023-01-26-formally-verifying-solana-programs/](https://osec.io/blog/2023-01-26-formally-verifying-solana-programs/)   
[https://github.com/sannykim/solsec.git](https://github.com/sannykim/solsec.git)   
[https://www.oswar.org/\#oswar](https://www.oswar.org/#oswar)   
[https://red.anthropic.com/2026/zero-days/](https://red.anthropic.com/2026/zero-days/)   
[https://red.anthropic.com/2026/cyber-toolkits-update/](https://red.anthropic.com/2026/cyber-toolkits-update/)   
[https://red.anthropic.com/2026/property-based-testing/](https://red.anthropic.com/2026/property-based-testing/)   
[https://red.anthropic.com/2026/critical-infrastructure-defense/](https://red.anthropic.com/2026/critical-infrastructure-defense/)   
[https://red.anthropic.com/2025/smart-contracts/](https://red.anthropic.com/2025/smart-contracts/)   
[https://red.anthropic.com/2025/ai-for-cyber-defenders/](https://red.anthropic.com/2025/ai-for-cyber-defenders/)   
[https://papers.ssrn.com/sol3/papers.cfm?abstract\_id=6552478](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6552478)   
[https://www.chaincatcher.com/en/article/2225557](https://www.chaincatcher.com/en/article/2225557)   
[https://blog.chalda.cz/posts/solana-fuzz-testing/](https://blog.chalda.cz/posts/solana-fuzz-testing/)   
[https://mpp.dev/llms.txt](https://mpp.dev/llms.txt)   
[https://vibraniumaudits.com/post/how-to-audit-solana-smart-contracts](https://vibraniumaudits.com/post/how-to-audit-solana-smart-contracts)   
[https://hashlock.com/blog/how-to-become-a-smart-contract-auditor-and-get-a-job\#elementor-toc\_\_heading-anchor-2](https://hashlock.com/blog/how-to-become-a-smart-contract-auditor-and-get-a-job#elementor-toc__heading-anchor-2)   
[https://hashlock.com/blog/how-to-become-a-smart-contract-auditor-and-get-a-job\#elementor-toc\_\_heading-anchor-3](https://hashlock.com/blog/how-to-become-a-smart-contract-auditor-and-get-a-job#elementor-toc__heading-anchor-3)   
[https://hashlock.com/blog/how-to-become-a-smart-contract-auditor-and-get-a-job\#elementor-toc\_\_heading-anchor-4](https://hashlock.com/blog/how-to-become-a-smart-contract-auditor-and-get-a-job#elementor-toc__heading-anchor-4)   
[https://hashlock.com/smart-contract-audit-cost-calculator](https://hashlock.com/smart-contract-audit-cost-calculator)   
[https://www.zealynx.io/blogs/solana-2026-security](https://www.zealynx.io/blogs/solana-2026-security)   
[https://giveth.io/project/auditing-in-the-ai-era-open-course](https://giveth.io/project/auditing-in-the-ai-era-open-course)   
[https://github.com/Ackee-Blockchain/solana-handbook.git](https://github.com/Ackee-Blockchain/solana-handbook.git)   
[https://ackee.xyz/trident/docs/latest/trident-api/](https://ackee.xyz/trident/docs/latest/trident-api/)   
[https://ackee.xyz/trident/docs/latest/trident-advanced/](https://ackee.xyz/trident/docs/latest/trident-advanced/)   
\[19:01, 08/05/2026\] Nyoko Karma N.: https://www.provos.org/p/finding-zero-days-with-any-model/  
\[19:02, 08/05/2026\] Nyoko Karma N.: https://github.com/provos/ironcurtain  
\[20:21, 08/05/2026\] Nyoko Karma N.: https://ackee.xyz/blog/vibe-fuzzing-guide-for-wakes-manually-guided-fuzzing/  
\[20:21, 08/05/2026\] Nyoko Karma N.: https://giveth.io/project/auditing-in-the-ai-era-open-course  
\[20:22, 08/05/2026\] Nyoko Karma N.: https://ackee.xyz/solana/book/latest/  
\[20:23, 08/05/2026\] Nyoko Karma N.: https://ackee.xyz/blog/trident-brings-manually-guided-fuzzing-to-solana/  
\[20:29, 08/05/2026\] Nyoko Karma N.: https://ackee.xyz/blog/trident-arena-multi-agent-ai-security-for-solana-programs/

—

**\# Research**

[https://arxiv.org/pdf/2409.01382](https://arxiv.org/pdf/2409.01382)  
[https://arxiv.org/pdf/2401.11314](https://arxiv.org/pdf/2401.11314)   
[https://arxiv.org/pdf/2301.10016](https://arxiv.org/pdf/2301.10016)   
[https://arxiv.org/pdf/2304.02491](https://arxiv.org/pdf/2304.02491)   
[https://arxiv.org/pdf/1905.08085](https://arxiv.org/pdf/1905.08085)   
[https://arxiv.org/html/2404.12135v2](https://arxiv.org/html/2404.12135v2)   
[https://arxiv.org/pdf/2410.09381](https://arxiv.org/pdf/2410.09381)   
[https://arxiv.org/pdf/2309.03006](https://arxiv.org/pdf/2309.03006)   
[https://arxiv.org/pdf/2304.06341](https://arxiv.org/pdf/2304.06341)   
[https://arxiv.org/pdf/2301.03943](https://arxiv.org/pdf/2301.03943)   
[https://dl.acm.org/doi/pdf/10.1145/3643916.3644406](https://dl.acm.org/doi/pdf/10.1145/3643916.3644406)   
[https://scholarworks.iu.edu/iuswrrest/api/core/bitstreams/76a6a22f-ec92-4a2f-912b-4b5275ec7040/content](https://scholarworks.iu.edu/iuswrrest/api/core/bitstreams/76a6a22f-ec92-4a2f-912b-4b5275ec7040/content)   
[https://arxiv.org/pdf/2406.13599](https://arxiv.org/pdf/2406.13599) 

—

**\# Tools yang di Integrasi & Orchestrasi**

[https://github.com/exo-tech-xyz/auditor-architecture-template.git](https://github.com/exo-tech-xyz/auditor-architecture-template.git)   
[https://docs.rs/cargo-audit/latest/cargo\_audit/](https://docs.rs/cargo-audit/latest/cargo_audit/)   
[https://crates.io/crates/cargo-geiger](https://crates.io/crates/cargo-geiger)   
[https://github.com/pratikbuilds/anchor-UI](https://github.com/pratikbuilds/anchor-UI)   
[https://github.com/Ackee-Blockchain/trident.git](https://github.com/Ackee-Blockchain/trident.git)   
[https://github.com/blockworks-foundation/checked-math.git](https://github.com/blockworks-foundation/checked-math.git)   
[https://github.com/otter-sec/sol-ctf-framework.git](https://github.com/otter-sec/sol-ctf-framework.git)   
[https://github.com/neodyme-labs/solana-poc-framework.git](https://github.com/neodyme-labs/solana-poc-framework.git)   
[https://github.com/saber-hq/vipers.git](https://github.com/saber-hq/vipers.git)   
[https://github.com/model-checking/kani.git](https://github.com/model-checking/kani.git)   
[https://github.com/trailofbits/necessist.git](https://github.com/trailofbits/necessist.git)   
[https://github.com/trailofbits/dylint.git](https://github.com/trailofbits/dylint.git)   
[https://github.com/trailofbits/test-fuzz.git](https://github.com/trailofbits/test-fuzz.git)   
[https://github.com/otter-sec/qemu-escape.git](https://github.com/otter-sec/qemu-escape.git)   
[https://github.com/otter-sec/otter-verify.git](https://github.com/otter-sec/otter-verify.git)   
[https://github.com/otter-sec/solana-verified-programs-api.git](https://github.com/otter-sec/solana-verified-programs-api.git)   
[https://github.com/saber-hq/vipers.git](https://github.com/saber-hq/vipers.git)    
[https://github.com/saber-hq/saber-common.git](https://github.com/saber-hq/saber-common.git)   
[https://github.com/model-checking/cbmc-viewer.git](https://github.com/model-checking/cbmc-viewer.git)   
[https://github.com/model-checking/cbmc-starter-kit.git](https://github.com/model-checking/cbmc-starter-kit.git)   
[https://github.com/kubescape/kubescape.git](https://github.com/kubescape/kubescape.git)   
[https://github.com/sec3-product/x-ray.git](https://github.com/sec3-product/x-ray.git)   
[https://github.com/sec3-service/IDLGuesser.git](https://github.com/sec3-service/IDLGuesser.git) 

—  
\# Agent Framework  
[https://github.com/anthropics/claude-code.git](https://github.com/anthropics/claude-code.git)   
[https://openrouter.ai/docs/quickstart/llms-full.txt](https://openrouter.ai/docs/quickstart/llms-full.txt)   
[https://github.com/anomalyco/opencode.git](https://github.com/anomalyco/opencode.git)   
[https://github.com/OpenRouterTeam/typescript-sdk.git](https://github.com/OpenRouterTeam/typescript-sdk.git)   
[https://github.com/anomalyco/opentui.git](https://github.com/anomalyco/opentui.git) 

\# Agent Skills Skills.sh  
[https://skills.sh/trailofbits](https://skills.sh/trailofbits)   
[https://skills.sh/qedgen/solana-skills](https://skills.sh/qedgen/solana-skills)   
[https://github.com/sendaifun/skills/tree/main/skills/zz-code-recon](https://github.com/sendaifun/skills/tree/main/skills/zz-code-recon)   
[https://github.com/sendaifun/skills/tree/main/skills/vulnhunter](https://github.com/sendaifun/skills/tree/main/skills/vulnhunter)   
[https://skills.sh/trailofbits/skills/solana-vulnerability-scanner](https://skills.sh/trailofbits/skills/solana-vulnerability-scanner) 

—-

\# Dataset  
[https://drive.google.com/drive/folders/1P53xJtCLsXnmYH76LoUN8i-krepSoVRB?usp=sharing](https://drive.google.com/drive/folders/1P53xJtCLsXnmYH76LoUN8i-krepSoVRB?usp=sharing) 

—-

\# Color Pallate Option Theme

[https://colorhunt.co/palette/f777540187900a516d2b2726](https://colorhunt.co/palette/f777540187900a516d2b2726)  
[https://colorhunt.co/palette/faf7f0d8d2c2b174574a4947](https://colorhunt.co/palette/faf7f0d8d2c2b174574a4947)   
[https://colorhunt.co/palette/fe7743efeeea273f4f000000](https://colorhunt.co/palette/fe7743efeeea273f4f000000)   
[https://colorhunt.co/palette/f7f7f7eeeeee393e46929aab](https://colorhunt.co/palette/f7f7f7eeeeee393e46929aab)   
[https://colorhunt.co/palette/2e2b2b388186a5e9e1fdf6f6](https://colorhunt.co/palette/2e2b2b388186a5e9e1fdf6f6) 

—  
\#referensi ui/ux web  
[https://ampcode.com/](https://ampcode.com/) 

—  
\# Skill Ui/Ux 

npx skills add https://github.com/anthropics/skills \--skill frontend-design   
npx skills add vercel-labs/agent-skills  
npx skills add google-labs-code/stitch-skills  
npx skills add vercel-labs/vercel-skills   
npx skills add google-labs-code/[design.md](http://design.md) 

—  
\# Video Intro  
npx skills add remotion-dev/html-in-canvas  
npx skills add remotion-dev/skills  
npx skills add remotion-dev/remotion  
npx create-video@latest

—-

\# Benchmark

[https://github.com/ConsenSysDiligence/daedaluzz.git](https://github.com/ConsenSysDiligence/daedaluzz.git)   
[https://github.com/Ackee-Blockchain/trident-arena-benchmarks.git](https://github.com/Ackee-Blockchain/trident-arena-benchmarks.git)    
[https://github.com/ConsenSysDiligence/smart-contract-best-practices.git](https://github.com/ConsenSysDiligence/smart-contract-best-practices.git) 

**Multi-agent AI for Solana**  
[**https://ackee.xyz/blog/trident-arena-multi-agent-ai-security-for-solana-programs/**](https://ackee.xyz/blog/trident-arena-multi-agent-ai-security-for-solana-programs/)   
Deep security reasoning built for Solana programs.  
Not a generic LLM wrapper. Multi-agent AI with Solana-specific expertise analyzes your code with the same reasoning auditors use:

* Protocol-specific vulnerabilities  
* Logic flaws and edge cases  
* Security issues unique to Solana  
* Real findings from real audits

