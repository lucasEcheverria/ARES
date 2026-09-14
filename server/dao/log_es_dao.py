"""Data Access Object for agent logs stored in Elasticsearch."""

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from elasticsearch import AsyncElasticsearch

INDEX = "ares-logs"

# Standard RRF rank constant (matches Elasticsearch's own default for
# `retriever.rrf`), used when fusing search results client-side.
_RRF_RANK_CONSTANT = 60

# MariaDB graph events mirrored into this index for RAG embedding (see
# rag_indexing_service.py) don't carry the tool_result-shaped fields
# (`tool`, `exit_code`, `lines`) that LogEntry/get_logs expects — exclude
# them from the raw tool-output log viewer's query.
_MIRRORED_EVENT_TYPES = ["thought", "tool_call", "phase_change"]


class LogEsDAO:
    """Persistence operations for agent log documents in the `ares-logs` index."""

    def __init__(self, client: AsyncElasticsearch) -> None:
        """Initialize the DAO.

        Args:
            client: Async Elasticsearch client.
        """
        self._client = client

    async def get_logs(
        self,
        session_id: str,
        phase: str | None = None,
        tool: str | None = None,
        from_dt: str | None = None,
        to_dt: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Query logs from Elasticsearch for a given session with optional filters.

        Args:
            session_id: Filter by session ID (always required).
            phase: Optional filter by phase (exact match, keyword).
            tool: Optional filter by tool name (exact match, keyword).
            from_dt: Optional ISO datetime string for lower bound on created_at.
            to_dt: Optional ISO datetime string for upper bound on created_at.
            limit: Maximum number of results to return (default 50).
            offset: Number of results to skip for pagination (default 0).

        Returns:
            dict with keys:
                - total: int — total number of matching documents
                - logs: list[dict] — the log documents for this page
        """
        filters: list[dict[str, Any]] = [{"term": {"session_id": session_id}}]
        if phase is not None:
            filters.append({"term": {"phase": phase}})
        if tool is not None:
            filters.append({"term": {"tool": tool}})
        if from_dt is not None or to_dt is not None:
            date_range: dict[str, str] = {}
            if from_dt is not None:
                date_range["gte"] = from_dt
            if to_dt is not None:
                date_range["lte"] = to_dt
            filters.append({"range": {"created_at": date_range}})

        result = await self._client.search(
            index=INDEX,
            query={
                "bool": {
                    "filter": filters,
                    "must_not": [{"terms": {"type": _MIRRORED_EVENT_TYPES}}],
                }
            },
            sort=[{"created_at": "asc"}],
            from_=offset,
            size=limit,
        )

        return {
            "total": result["hits"]["total"]["value"],
            "logs": [hit["_source"] for hit in result["hits"]["hits"]],
        }

    async def insert_log(self, log: dict[str, Any]) -> None:
        """Index a single log document into `ares-logs`.

        Args:
            log: The log document; must contain an `id` field used as the document ID.
        """
        await self._client.index(index=INDEX, id=log["id"], document=log)

    async def delete_logs_by_session(self, session_id: str) -> None:
        """Delete all logs for a given session (for cleanup).

        Args:
            session_id: The session whose logs should be deleted.
        """
        await self._client.delete_by_query(
            index=INDEX,
            query={"term": {"session_id": session_id}},
        )

    async def get_all_by_session(self, session_id: str) -> list[dict[str, Any]]:
        """Fetch every document already indexed in `ares-logs` for a session.

        Used by the RAG indexing service to (re-)embed existing `tool_result`
        documents, written directly to ES by the agent's `es_logger`.

        Args:
            session_id: The owning session's UUID.

        Returns:
            List of raw ES documents (`_source`), each with its `id` from `_id`.
        """
        documents: list[dict[str, Any]] = []
        async for hit in self._scan(
            query={"term": {"session_id": session_id}},
        ):
            document = hit["_source"]
            document["id"] = hit["_id"]
            documents.append(document)
        return documents

    async def _scan(self, query: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
        """Yield every hit matching `query`, paginating past the default size cap.

        Args:
            query: Elasticsearch query clause.

        Yields:
            Raw hit dicts (with `_id` and `_source`).
        """
        page_size = 500
        offset = 0
        while True:
            result = await self._client.search(
                index=INDEX,
                query=query,
                from_=offset,
                size=page_size,
            )
            hits = result["hits"]["hits"]
            for hit in hits:
                yield hit
            if len(hits) < page_size:
                return
            offset += page_size

    async def update_embedding(self, doc_id: str, vector: list[float]) -> None:
        """Partially update a document's `embedding` field.

        Args:
            doc_id: The document's `_id`.
            vector: Embedding vector to store.
        """
        await self._client.update(
            index=INDEX,
            id=doc_id,
            doc={"embedding": vector},
        )

    async def hybrid_search(
        self,
        session_id: str,
        query_text: str,
        query_vector: list[float],
        k: int = 8,
    ) -> list[dict[str, Any]]:
        """Retrieve the top matching documents for a session via kNN + BM25 fused with RRF.

        The lexical leg matches against both `content` (MariaDB-sourced thought/
        tool_call/phase_change events, mirrored into ES for embedding) and
        `lines` (ES-native tool_result output), since a document only ever
        populates one of the two depending on its origin.

        Fusion is computed client-side with the standard Reciprocal Rank
        Fusion formula, rather than via Elasticsearch's native `retriever.rrf`
        — that retriever requires a licensed (non-Basic) cluster, so relying
        on it would break on any free-tier Elasticsearch install.

        Args:
            session_id: Scope the search to this session only.
            query_text: Natural-language question, used for the lexical (BM25) leg.
            query_vector: Embedding of `query_text`, used for the semantic (kNN) leg.
            k: Number of results to return.

        Returns:
            List of matching ES documents (`_source`), each with its `id` from `_id`,
            sorted by fused RRF score descending.
        """
        knn_result, lexical_result = await asyncio.gather(
            self._client.search(
                index=INDEX,
                knn={
                    "field": "embedding",
                    "query_vector": query_vector,
                    "k": k,
                    "num_candidates": max(k * 10, 50),
                    "filter": {"term": {"session_id": session_id}},
                },
                size=k,
            ),
            self._client.search(
                index=INDEX,
                query={
                    "bool": {
                        "must": [
                            {
                                "multi_match": {
                                    "query": query_text,
                                    "fields": ["content", "lines"],
                                }
                            }
                        ],
                        "filter": [{"term": {"session_id": session_id}}],
                    }
                },
                size=k,
            ),
        )

        fused = self._reciprocal_rank_fusion(
            [knn_result["hits"]["hits"], lexical_result["hits"]["hits"]]
        )
        return fused[:k]

    def _reciprocal_rank_fusion(
        self, ranked_hit_lists: list[list[dict[str, Any]]]
    ) -> list[dict[str, Any]]:
        """Fuse multiple ranked ES hit lists into one, via Reciprocal Rank Fusion.

        Args:
            ranked_hit_lists: One list of ES hits per retriever leg, each
                already sorted by relevance (as returned by Elasticsearch).

        Returns:
            Documents (`_source` plus `id`), deduplicated across legs and
            sorted by fused RRF score descending.
        """
        scores: dict[str, float] = {}
        documents: dict[str, dict[str, Any]] = {}

        for hits in ranked_hit_lists:
            for rank, hit in enumerate(hits, start=1):
                doc_id = hit["_id"]
                scores[doc_id] = scores.get(doc_id, 0.0) + 1 / (_RRF_RANK_CONSTANT + rank)
                if doc_id not in documents:
                    document = hit["_source"]
                    document["id"] = doc_id
                    documents[doc_id] = document

        ranked_ids = sorted(scores, key=lambda doc_id: scores[doc_id], reverse=True)
        return [documents[doc_id] for doc_id in ranked_ids]
