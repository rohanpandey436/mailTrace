from __future__ import annotations

from fastapi.testclient import TestClient

from app.core import pipeline
from app.database.case_manager import Store
from app.main import create_app
from app.schemas import AnalysisResult, GeoInfo

AMSTERDAM = (52.37, 4.89, "Amsterdam", "The Netherlands")
LAGOS = (6.45, 3.39, "Lagos", "Nigeria")


def _place(store: Store, result: AnalysisResult, place: tuple[float, float, str, str]) -> None:
    lat, lon, city, country = place
    geo = GeoInfo(ip=result.headers.originating_ip or "", lat=lat, lon=lon, city=city, country=country)
    infrastructure = result.infrastructure.model_copy(update={"origin_geo": geo})
    store.save_analysis(result.model_copy(update={"infrastructure": infrastructure}), None)


def test_origins_group_listed_cases_by_sending_address(store: Store, cfg, sample):
    first = pipeline.analyze_bytes(sample("phishing"), "one.eml", store, cfg)
    second = pipeline.analyze_bytes(sample("phishing"), "two.eml", store, cfg)
    other = pipeline.analyze_bytes(sample("bec"), "bec.eml", store, cfg)
    assert first.id != second.id
    assert first.headers.originating_ip and other.headers.originating_ip
    assert first.headers.originating_ip != other.headers.originating_ip

    assert store.origins() == []

    _place(store, first, AMSTERDAM)
    _place(store, second, AMSTERDAM)
    _place(store, other, LAGOS)
    points = store.origins()

    assert [(point.ip, point.emails, point.city, point.country) for point in points] == [
        (first.headers.originating_ip, 2, "Amsterdam", "The Netherlands"),
        (other.headers.originating_ip, 1, "Lagos", "Nigeria"),
    ]
    assert (points[0].lat, points[0].lon) == (52.37, 4.89)
    assert points[0].max_risk == max(first.verdict.risk_score, second.verdict.risk_score)


def test_origins_leave_out_private_cases_and_untraced_ones(store: Store, cfg, sample):
    listed = pipeline.analyze_bytes(sample("phishing"), "listed.eml", store, cfg)
    private = pipeline.analyze_bytes(sample("phishing"), "private.eml", store, cfg)
    pipeline.analyze_bytes(sample("legit"), "untraced.eml", store, cfg)
    _place(store, listed, AMSTERDAM)
    _place(store, private, AMSTERDAM)
    store.set_retention(private.id, "gmail", False, None, private.email.raw_sha256)

    points = store.origins()

    assert [(point.ip, point.emails) for point in points] == [(listed.headers.originating_ip, 1)]


def test_the_api_serves_the_origins(cfg, sample):
    with TestClient(create_app(cfg)) as client:
        assert client.get("/api/origins").json() == []
        store: Store = client.app.state.store
        result = pipeline.analyze_bytes(sample("phishing"), "one.eml", store, cfg)
        _place(store, result, AMSTERDAM)

        assert client.get("/api/origins").json() == [
            {
                "ip": result.headers.originating_ip,
                "lat": 52.37,
                "lon": 4.89,
                "city": "Amsterdam",
                "country": "The Netherlands",
                "emails": 1,
                "max_risk": result.verdict.risk_score,
            }
        ]
