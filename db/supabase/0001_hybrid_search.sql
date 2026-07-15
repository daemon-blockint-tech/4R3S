-- ARES hybrid knowledge base — Supabase schema.
--
-- Documents and chunks with pgvector embeddings and a full-text tsvector, plus
-- a `hybrid_search` function that fuses semantic (vector) and lexical
-- (full-text) rankings with Reciprocal Rank Fusion (RRF).
--
-- Apply with the Supabase SQL editor or `supabase db push`.
-- NOTE: the embedding dimension below (1536) must match EMBEDDINGS_DIM.

create extension if not exists vector;

create table if not exists documents (
  doc_id     text primary key,
  title      text,
  path       text,
  created_at timestamptz not null default now()
);

create table if not exists chunks (
  chunk_id    text primary key,
  doc_id      text not null references documents (doc_id) on delete cascade,
  content     text not null,
  chunk_index int  not null default 0,
  embedding   vector(1536),
  fts         tsvector generated always as (to_tsvector('english', content)) stored,
  created_at  timestamptz not null default now()
);

create index if not exists chunks_fts_idx on chunks using gin (fts);
create index if not exists chunks_embedding_idx
  on chunks using hnsw (embedding vector_cosine_ops);
create index if not exists chunks_doc_id_idx on chunks (doc_id);

-- Hybrid search: RRF over full-text rank and vector similarity.
-- `query_embedding` may be null (lexical-only), in which case only the
-- full-text ranking contributes.
create or replace function hybrid_search(
  query_text     text,
  query_embedding vector(1536) default null,
  match_count    int default 20,
  full_text_weight float default 1.0,
  semantic_weight  float default 1.0,
  rrf_k          int default 50
)
returns table (
  chunk_id  text,
  doc_id    text,
  entity_id text,
  content   text,
  score     float
)
language sql
stable
as $$
with full_text as (
  select
    c.chunk_id,
    row_number() over (
      order by ts_rank_cd(c.fts, websearch_to_tsquery('english', query_text)) desc
    ) as rank_ix
  from chunks c
  where c.fts @@ websearch_to_tsquery('english', query_text)
  order by rank_ix
  limit least(match_count, 200) * 2
),
semantic as (
  select
    c.chunk_id,
    row_number() over (
      order by c.embedding <=> query_embedding
    ) as rank_ix
  from chunks c
  where query_embedding is not null and c.embedding is not null
  order by rank_ix
  limit least(match_count, 200) * 2
)
select
  c.chunk_id,
  c.doc_id,
  null::text as entity_id,
  c.content,
  (
    coalesce(full_text_weight / (rrf_k + full_text.rank_ix), 0.0) +
    coalesce(semantic_weight  / (rrf_k + semantic.rank_ix), 0.0)
  ) as score
from full_text
full outer join semantic on full_text.chunk_id = semantic.chunk_id
join chunks c
  on c.chunk_id = coalesce(full_text.chunk_id, semantic.chunk_id)
order by score desc
limit least(match_count, 200);
$$;
