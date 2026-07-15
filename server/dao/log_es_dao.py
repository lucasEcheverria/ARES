"""Data Access Object for agent logs stored in Elasticsearch."""

from typing import Any

from elasticsearch import AsyncElasticsearch

INDEX = "ares-logs"


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
        type: str | None = None,
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
            type: Optional filter by event type (exact match, keyword).
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
        if type is not None:
            filters.append({"term": {"type": type}})
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
            query={"bool": {"filter": filters}},
            sort=[{"sequence": "asc"}],
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
