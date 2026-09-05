"""
Campaign and relationship-graph endpoints.

A campaign view is a projection over its member analyses: the member rows
come straight from the store and the graph is ``graph_builder.merge_graphs``
over every member's stored graph, which adds the campaign node and marks the
pivot nodes shared by several emails.  When PII masking is requested each
member result is masked *before* merging, so address nodes carry the same
hashed id across members and still merge correctly.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query

from ..core import decisions
from ..core import graph_builder as graph_engine
from ..core.errors import NotFound
from ..database.case_manager import Store
from ..schemas import AnalysisResult, AttributionGraph, Campaign, CampaignDetail
from ..utils.pii_masker import mask_result
from .deps import MaskDep, StoreDep, mask_summary

router = APIRouter(prefix="/api", tags=["cases"])


def _load_campaign(store: Store, campaign_id: str) -> Campaign:
    campaign = store.get_campaign(campaign_id)
    if campaign is None:
        raise NotFound(f"campaign {campaign_id} not found")
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
def list_campaigns(store: StoreDep) -> list[Campaign]:
    return store.list_campaigns()


@router.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: str, store: StoreDep, mask: MaskDep) -> CampaignDetail:
    campaign = _load_campaign(store, campaign_id)
    emails = store.summaries_for(campaign.email_ids)
    if mask:
        emails = [mask_summary(summary) for summary in emails]
    return CampaignDetail(campaign=campaign, emails=emails, graph=_campaign_graph(store, campaign, mask))


@router.get("/graph")
def get_graph(
    store: StoreDep,
    mask: MaskDep,
    email_id: Annotated[str | None, Query()] = None,
    campaign_id: Annotated[str | None, Query()] = None,
) -> AttributionGraph:
    if email_id:
        result = decisions.load_case(store, email_id)
        return (mask_result(result) if mask else result).graph
    if campaign_id:
        return _campaign_graph(store, _load_campaign(store, campaign_id), mask)
    raise HTTPException(status_code=400, detail="email_id or campaign_id is required")
