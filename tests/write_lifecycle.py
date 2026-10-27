"""Assertions for installed write/readback, explicit retests and frozen reports."""

import hashlib


def write_case(origin, identities):
    actors = identities[:2]
    reader = {
        **actors[0],
        "id": "reader",
        "credential": {"type": "bearer", "value_env": "FIXTURE_READER_TOKEN"},
        "preflight": {
            "url": origin + "/session",
            "expected_status": 200,
            "json_fields": {"user.id": "reader"},
        },
    }
    return {
        "name": "write",
        "spec": {
            "id": "installed-write",
            "mutating": True,
            "require_identity_preflight": True,
            "identities": actors,
            "expected_access": [
                {
                    "identity_id": i["id"],
                    "decision": "allow" if i["id"] == "owner" else "deny",
                }
                for i in actors
            ],
            "resource": {
                "type": "record",
                "object_id": "42",
                "owner_identity": "owner",
                "tenant_id": "fixture-tenant",
            },
            "request": {
                "method": "PUT",
                "url": origin + "/verification/write",
                "body": {"value": "fixture-write-marker"},
            },
            "write_verification": {
                "strategy": "changed",
                "environment": "synchronous_isolated",
                "identity": reader,
                "request": {"method": "GET", "url": origin + "/verification/state"},
                "json_pointer": "/value",
                "changed_to": "fixture-write-marker",
                "reset": {
                    "as": "owner",
                    "request": {"method": "PUT", "url": origin + "/verification/reset"},
                },
            },
        },
    }


def verify_write(assessment, evidence, scenario):
    assert assessment["status"] == "conclusive" and assessment["baseline_valid"] is True
    identities = {i["identity_id"]: i for i in assessment["identities"]}
    assert set(identities) == {"owner", "peer"} and assessment["evaluated"] == 2
    for who, item in identities.items():
        proof = item["verification"]
        assert item["source"] == "write_verification" and item["state"] == "evaluated"
        assert (
            proof["reader_identity_id"] == "reader"
            and proof["reader_credential_status"] == "preflight_passed"
        )
        assert (
            proof["before_statuses"] == [200, 200]
            and proof["after_status"] == 200
            and proof["reset_status"] == 204
        )
        assert (
            proof["strategy"] == "changed"
            and proof["environment"] == "synchronous_isolated"
        )
        allowed = who == "owner" or scenario == "write-vulnerable"
        assert item["reported_decision"] == ("allowed" if allowed else "denied")
        assert item["write_verification"] == (
            "verified_effect" if allowed else "verified_no_effect"
        )
    resources = [e for e in evidence if e["expected_decision"] in {"allow", "deny"}]
    assert len(resources) == 2
    assert all(
        '"status_code": 204' in e["body"]
        and '"reader_identity_id": "reader"' in e["body"]
        for e in resources
    )
    assert all(
        '"value": "initial"' not in e["body"]
        and '"value": "fixture-write-marker"' not in e["body"]
        for e in evidence
    )


def verify_write_traffic(traffic, scenario):
    assert len(traffic) == 13, traffic
    assert [(r["identity"], r["path"]) for r in traffic[:3]] == [
        (i, "/session") for i in ("owner", "peer", "reader")
    ]
    reads = [r for r in traffic if r["path"] == "/verification/state"]
    resets = [r for r in traffic if r["path"] == "/verification/reset"]
    writes = [r for r in traffic if r["path"] == "/verification/write"]
    assert len(reads) == 6 and all(
        r["identity"] == "reader" and r["method"] == "GET" for r in reads
    )
    assert len(resets) == 2 and all(
        r["identity"] == "owner" and r["method"] == "PUT" for r in resets
    )
    assert {r["identity"]: r["changed"] for r in writes} == {
        "owner": True,
        "peer": scenario == "write-vulnerable",
    }, writes
    for start in (3, 8):
        cycle = traffic[start : start + 5]
        assert [r["path"] for r in cycle] == [
            "/verification/reset",
            "/verification/state",
            "/verification/state",
            "/verification/write",
            "/verification/state",
        ]


def delivery_snapshot(request, base, finding_id, report_id):
    finding = next(
        f for f in request(base + "/findings")["findings"] if f["id"] == finding_id
    )
    path = f"{base}/deliverables/{report_id}/revisions"
    versions = request(path)["revisions"]
    revisions = {
        str(v["revision"]): request(path + "/" + str(v["revision"])) for v in versions
    }
    for revision in revisions.values():
        assert revision["status"] == "delivered"
        assert (
            hashlib.sha256(revision["markdown"].encode()).hexdigest()
            == revision["content_hash"]
        )
        assert len(revision["snapshot"]["findings"]) == 1
        assert revision["snapshot"]["findings"][0]["id"] == finding_id
        assert (
            revision["snapshot"]["engagement"]["client"] == "Disposable fixture client"
        )
        assert revision["snapshot"]["scope"] and revision["snapshot"]["authorizations"]
        assert (
            revision["snapshot"]["engagement"]["starts_at"]
            and revision["snapshot"]["engagement"]["ends_at"]
        )
        for e in revision["snapshot"]["evidence"]:
            assert hashlib.sha256(e["body"].encode()).hexdigest() == e["content_hash"]
    linked = request(base + f"/evidence?finding_id={finding_id}")["evidence"]
    return {
        "finding": finding,
        "report": report_id,
        "revisions": revisions,
        "activity": request(base + f"/findings/{finding_id}/activity")["activities"],
        "links": {e["id"]: finding_id for e in linked},
        "evidence_hashes": {e["id"]: e["content_hash"] for e in linked},
    }


def verify_delivery(delivery):
    assert delivery["finding"]["status"] == "closed"
    assert set(delivery["revisions"]) == {"1", "2"}
    first, second = delivery["revisions"]["1"], delivery["revisions"]["2"]
    assert first["snapshot"]["findings"][0]["status"] == "triaged"
    assert second["snapshot"]["findings"][0]["status"] == "closed"
    assert any(a["outcome"] == "still_open" for a in first["snapshot"]["activity"])
    assert not any(
        a["outcome"] == "verified_fixed" for a in first["snapshot"]["activity"]
    )
    assert any(a["outcome"] == "verified_fixed" for a in second["snapshot"]["activity"])
    assert len(delivery["links"]) == 2
    references = []
    for outcome in ("still_open", "verified_fixed"):
        activity = next(a for a in delivery["activity"] if a["outcome"] == outcome)
        assert len(activity["evidence"]) == 1
        assert activity["evidence"][0]["id"] in delivery["links"]
        reference = activity["evidence"][0]
        assert reference["content_hash"] == delivery["evidence_hashes"][reference["id"]]
        assert reference["identity_id"] == "peer"
        references.append(reference)
    assert (
        references[0]["id"] != references[1]["id"]
        and references[0]["job_id"] != references[1]["job_id"]
    )
    assert references[0]["case_id"] == references[1]["case_id"]
    assert first["content_hash"] != second["content_hash"]
