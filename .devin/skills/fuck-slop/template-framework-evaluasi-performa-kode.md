# Framework Evaluasi Performa Kode

Gunakan template ini untuk mengevaluasi performa service, worker, pipeline, library, endpoint, atau job batch secara konsisten. Fokus template ini adalah membedakan masalah correctness, bottleneck sistemik, hidden cost, dan scaling behavior.

## 1. Ringkasan Evaluasi

**Nama komponen:**  
**Owner:**  
**Tanggal evaluasi:**  
**Versi/commit:**  
**Environment:** local / staging / production  
**Evaluator:**  
**Status:** Green / Yellow / Red  

**Tujuan komponen:**  
Jelaskan fungsi bisnis atau fungsi teknis dari komponen yang dievaluasi.

**Unit kerja utama:**  
Contoh: per request, per event, per batch, per transaction, per file, per message.

**Target performa / SLO:**  
Contoh: p95 < 200 ms, error rate < 0.5%, memory peak < 512 MB, throughput > 500 jobs/minute.

**Kesimpulan singkat:**  
Tulis 3–5 kalimat tentang kondisi performa saat ini, bottleneck dominan, hidden cost utama, dan prioritas tindakan.

---

## 2. Konteks Beban Kerja

**Profil workload:**  
- Jenis beban: CPU-bound / I/O-bound / mixed
- Pola traffic: bursty / steady / batch / scheduled
- Ukuran input tipikal:
- Ukuran input terburuk:
- Tingkat concurrency normal:
- Tingkat concurrency puncak:

**Dependency utama:**  
- Database:
- Cache:
- Queue / broker:
- External API:
- Filesystem / object storage:
- Service lain:

**Asumsi penting:**  
Tuliskan constraint yang memengaruhi hasil, misalnya cold start, cache warmup, rate limit, koneksi antar region, atau data skew.

---

## 3. Baseline Metrik

Isi baseline dari workload yang representatif dan bisa diulang.

| Metrik | Nilai Saat Ini | Target | Status | Catatan |
|---|---:|---:|---|---|
| Latency p50 |  |  |  |  |
| Latency p95 |  |  |  |  |
| Latency p99 |  |  |  |  |
| Throughput |  |  |  |  |
| Error rate |  |  |  |  |
| Timeout rate |  |  |  |  |
| CPU avg |  |  |  |  |
| CPU peak |  |  |  |  |
| Memory avg |  |  |  |  |
| Memory peak |  |  |  |  |
| Allocation rate |  |  |  |  |
| GC / pause time |  |  |  |  |
| Query count / unit kerja |  |  |  |  |
| Network calls / unit kerja |  |  |  |  |
| Disk I/O / unit kerja |  |  |  |  |
| Retry count |  |  |  |  |
| Queue depth |  |  |  |  |
| Lock wait / contention |  |  |  |  |

**Sumber data baseline:**  
Contoh: benchmark lokal, profiling, tracing production, APM, load test, flamegraph, metrics dashboard.

---

## 4. Peta Hot Path

Deskripsikan alur eksekusi utama dari awal sampai akhir.

**Hot path utama:**  
1. Input masuk / request diterima  
2. Validasi  
3. Transformasi data  
4. Query / cache / API  
5. Compute utama  
6. Persist / publish / response  

**Langkah yang paling mahal:**  
Tandai langkah yang paling dominan dari sisi CPU, memori, I/O, lock, atau network.

**Apakah bottleneck ada di:**  
- [ ] Compute
- [ ] Memory allocation / copy
- [ ] Disk I/O
- [ ] Network I/O
- [ ] Database / query plan
- [ ] Cache miss
- [ ] Serialization / deserialization
- [ ] Lock / contention
- [ ] Retry / duplicate work
- [ ] Logging / observability overhead
- [ ] Framework / middleware overhead
- [ ] Lainnya:

---

## 5. Hidden Cost Audit

Gunakan bagian ini untuk mencari biaya yang tidak terlihat dari logic bisnis utama.

### 5.1 Alokasi dan Memori
- Apakah ada clone / copy besar yang bisa dihindari?
- Apakah ada object churn di loop?
- Apakah ada struktur data yang boros memori?
- Apakah ada payload yang dibangun penuh padahal hanya sebagian dipakai?
- Apakah ada memory growth atau leak pattern?

**Temuan:**  

### 5.2 Data Access
- Apakah ada N+1 query?
- Apakah query memuat kolom lebih banyak dari yang dibutuhkan?
- Apakah transaksi terlalu panjang?
- Apakah index sesuai pola query?
- Apakah ada full scan yang tidak disengaja?

**Temuan:**  

### 5.3 I/O dan Network
- Apakah ada call API / DB / file di dalam loop?
- Apakah request bisa dibatch?
- Apakah payload terlalu besar?
- Apakah ada reconnect atau handshake berulang?
- Apakah retry policy menciptakan amplifikasi traffic?

**Temuan:**  

### 5.4 Concurrency dan State
- Apakah ada lock scope yang terlalu lebar?
- Apakah ada shared mutable state?
- Apakah ada work duplication antar worker?
- Apakah queue depth naik saat load naik?
- Apakah tail latency memburuk saat concurrency naik?

**Temuan:**  

### 5.5 Serialization, Parsing, dan Transform
- Apakah data di-encode/decode berkali-kali?
- Apakah ada transform yang berulang antar layer?
- Apakah format data terlalu verbose?
- Apakah parsing dilakukan meski field tidak dibutuhkan?

**Temuan:**  

### 5.6 Observability Overhead
- Apakah logging terlalu verbose di hot path?
- Apakah trace/span dibuat terlalu granular?
- Apakah metric label high-cardinality?
- Apakah audit log menulis payload penuh tanpa kebutuhan jelas?

**Temuan:**  

---

## 6. Klasifikasi Bottleneck Dominan

Pilih klasifikasi utama dan jelaskan alasannya.

| Kategori | Ya/Tidak | Bukti | Dampak |
|---|---|---|---|
| Compute-bound |  |  |  |
| Memory-bound |  |  |  |
| I/O-bound |  |  |  |
| DB-bound |  |  |  |
| Network-bound |  |  |  |
| Contention-bound |  |  |  |
| Cache-efficiency issue |  |  |  |
| Framework overhead |  |  |  |
| Observability overhead |  |  |  |

**Kesimpulan bottleneck dominan:**  

---

## 7. Scaling Behavior

**Perilaku saat input membesar:**  
Jelaskan apakah performa memburuk secara linear, kuadratik, atau tidak terduga saat ukuran data bertambah.

**Perilaku saat concurrency naik:**  
Jelaskan perubahan pada p95/p99, queue depth, lock wait, CPU, memory, dan error rate.

**Perilaku saat dependency melambat:**  
Jelaskan dampak jika DB lambat, cache miss meningkat, external API timeout, atau storage melambat.

**Failure amplification:**  
Apakah retry, fan-out, atau duplicate execution memperparah kondisi saat sistem mulai gagal?

---

## 8. Metode Evaluasi yang Dipakai

Centang yang digunakan.

- [ ] Static code review
- [ ] Microbenchmark
- [ ] End-to-end benchmark
- [ ] CPU profiling
- [ ] Memory / heap profiling
- [ ] Allocation profiling
- [ ] Flamegraph
- [ ] Query analysis / EXPLAIN
- [ ] Distributed tracing
- [ ] Metrics dashboard review
- [ ] Load test
- [ ] Soak test
- [ ] Failure injection / chaos test

**Tool yang dipakai:**  
Contoh: pprof, perf, cargo flamegraph, benchmark.js, k6, Locust, OpenTelemetry, Grafana, Jaeger, EXPLAIN ANALYZE.

**Catatan validitas hasil:**  
Tulis apakah benchmark cukup representatif, ada noise, cache warm/cold effect, atau constraint environment lain.

---

## 9. Temuan Utama

| No | Temuan | Bukti | Dampak | Prioritas |
|---|---|---|---|---|
| 1 |  |  |  | High / Medium / Low |
| 2 |  |  |  | High / Medium / Low |
| 3 |  |  |  | High / Medium / Low |
| 4 |  |  |  | High / Medium / Low |

---

## 10. Rekomendasi Perbaikan

Gunakan format symptom → cause → fix → expected gain.

| Symptom | Likely Cause | Proposed Fix | Expected Gain | Risk |
|---|---|---|---|---|
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |

**Quick wins:**  
Tulis perubahan kecil dengan ROI tinggi.

**Structural fixes:**  
Tulis perubahan yang butuh refactor atau redesign.

**Yang tidak perlu dioptimalkan dulu:**  
Catat area yang terlihat jelek tapi belum berdampak material.

---

## 11. Rubrik Keputusan

### Green
Performa memenuhi target, tail latency terkendali, resource usage stabil, dan tidak ada hidden cost material.

### Yellow
Sistem masih lolos target minimum, tetapi ada hotspot, scaling risk, atau hidden cost yang akan jadi masalah saat load naik.

### Red
Target performa gagal, tail latency buruk, retry/contetion amplifies failure, atau cost per unit kerja sudah terlalu mahal.

**Status akhir evaluasi:**  
**Alasan status:**  

---

## 12. Action Plan

| Aksi | Owner | Prioritas | Estimasi usaha | Deadline | Status |
|---|---|---|---|---|---|
|  |  | High / Medium / Low |  |  | Not started |
|  |  | High / Medium / Low |  |  | In progress |
|  |  | High / Medium / Low |  |  | Done |

---

## 13. Re-evaluation

**Tanggal ukur ulang:**  
**Perubahan yang diuji:**  
**Hasil sebelum vs sesudah:**  

| Metrik | Sebelum | Sesudah | Delta | Catatan |
|---|---:|---:|---:|---|
| Latency p95 |  |  |  |  |
| Latency p99 |  |  |  |  |
| Throughput |  |  |  |  |
| CPU avg |  |  |  |  |
| Memory peak |  |  |  |  |
| Query count |  |  |  |  |
| Error rate |  |  |  |  |

**Apakah bottleneck berpindah?**  
Jelaskan apakah setelah optimasi, bottleneck utama bergeser ke layer lain.

---

## 14. Checklist Review Cepat

- [ ] Target performa jelas
- [ ] Baseline ada dan repeatable
- [ ] Hot path sudah dipetakan
- [ ] Hidden cost di luar logic utama sudah diaudit
- [ ] Latency p95/p99 diukur, bukan cuma rata-rata
- [ ] Cost per unit kerja dihitung
- [ ] Query / network / I/O amplification dicek
- [ ] Concurrency dan contention dicek
- [ ] Observability overhead dicek
- [ ] Ada prioritas tindakan yang jelas
- [ ] Ada rencana ukur ulang setelah fix

