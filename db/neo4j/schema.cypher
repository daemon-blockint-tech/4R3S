// ARES hybrid knowledge base — Neo4j schema.
//
// Node model:
//   (:Document { doc_id, title, path })
//   (:Chunk    { chunk_id, content, chunk_index, embedding? })
//   (:Entity   { entity_id, name })
// Relationships:
//   (:Document)-[:HAS_CHUNK]->(:Chunk)
//   (:Chunk)-[:MENTIONS]->(:Entity)
//
// IDs mirror the Supabase keys (doc_id / chunk_id / entity_id) so the two
// stores join. Applied by `npm run db:migrate` when Neo4j is configured.
// Statements are split on ';' by the migrate script — keep one per statement.

CREATE CONSTRAINT document_id IF NOT EXISTS
FOR (d:Document) REQUIRE d.doc_id IS UNIQUE;

CREATE CONSTRAINT chunk_id IF NOT EXISTS
FOR (c:Chunk) REQUIRE c.chunk_id IS UNIQUE;

CREATE CONSTRAINT entity_id IF NOT EXISTS
FOR (e:Entity) REQUIRE e.entity_id IS UNIQUE;

CREATE FULLTEXT INDEX chunk_content IF NOT EXISTS
FOR (c:Chunk) ON EACH [c.content];

CREATE VECTOR INDEX chunk_embedding IF NOT EXISTS
FOR (c:Chunk) ON (c.embedding)
OPTIONS { indexConfig: { `vector.dimensions`: 1536, `vector.similarity_function`: 'cosine' } };
