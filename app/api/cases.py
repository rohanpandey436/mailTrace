"""
Campaign and relationship-graph endpoints.

A campaign view is a projection over its member analyses: the member rows
come straight from the store and the graph is ``graph.merge_graphs`` over
every member's stored graph, which adds the campaign node and marks the
pivot nodes shared by several emails.  When PII masking is requested each
member result is masked *before* merging, so address nodes carry the same
hashed id across members and still merge correctly.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ..db import Store
from ..engine import graph as graph_engine
from ..engine.privacy import mask_result
from ..schemas import AnalysisResult, AttributionGraph, Campaign
from .deps import get_store, mask_param, mask_summary

router = APIRouter(prefix="/api", tags=["cases"])


def _load_campaign(store: Store, campaign_id: str) -> Campaign:
    campaign = store.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail=f"campaign {campaign_id} not found")
    return campaign


def _member_results(store: Store, campaign: Campaign, mask: bool) -> list[AnalysisResult]:
    results: list[AnalysisResult] = []
    for email_id in campaign.email_ids:
        result = store.get_analysis(email_id)
        if result is not None:
            results.append(mask_result(result) if mask else result)
    return results


def _campaign_graph(store: Store, campaign: Campaign, mask: bool) -> AttributionGraph:
    graphs = [result.graph for result in _member_results(store, campaign, mask)]
    return graph_engine.merge_graphs(graphs, campaign)


@router.get("/campaigns")
def list_campaigns(store: Store = Depends(get_store)) -> list[Campaign]:
    return store.list_campaigns()


@router.get("/campaigns/{campaign_id}")
def get_campaign(
    campaign_id: str,
    mask: bool = Depends(mask_param),
    store: Store = Depends(get_store),
) -> dict[str, Any]:
    campaign = _load_campaign(store, campaign_id)
    emails = store.summaries_for(campaign.email_ids)
    if mask:
        emails = [mask_summary(summary) for summary in emails]
    return {
        "campaign": campaign.model_dump(mode="json"),
        "emails": [summary.model_dump(mode="json") for summary in emails],
        "graph": _campaign_graph(store, campaign, mask).model_dump(mode="json"),
    }


@router.get("/graph")
def get_graph(
    email_id: Optional[str] = Query(None),
    campaign_id: Optional[str] = Query(None),
    mask: bool = Depends(mask_param),
    store: Store = Depends(get_store),
) -> AttributionGraph:
    if email_id:
        result = store.get_analysis(email_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"email {email_id} not found")
        return (mask_result(result) if mask else result).graph
    if campaign_id:
        return _campaign_graph(store, _load_campaign(store, campaign_id), mask)
    raise HTTPException(status_code=400, detail="email_id or campaign_id is required")
