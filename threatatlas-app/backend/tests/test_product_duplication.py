"""Tests for independent product duplication with reset security workflow state."""

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    Diagram,
    DiagramMitigation,
    DiagramThreat,
    DiagramThreatAttackTechnique,
    DiagramVersion,
    Framework,
    Mitigation,
    Model,
    Product,
    ProductCollaborator,
    Threat,
    User,
)
from app.models.enums import CollaboratorRole, UserRole
from app.models.model import ModelStatus
from tests.conftest import make_auth_headers


def _source_product(db: Session, owner: User) -> Product:
    framework = Framework(name="Clone framework", description="test")
    db.add(framework)
    db.flush()

    threat = Threat(framework_id=framework.id, name="Source threat")
    mitigation = Mitigation(framework_id=framework.id, name="Source mitigation")
    product = Product(
        user_id=owner.id,
        name="Source product",
        description="Copied description",
        is_public=True,
        status="production",
        jira_project_key="SOURCE",
    )
    db.add_all([threat, mitigation, product])
    db.flush()

    diagram = Diagram(
        product_id=product.id,
        created_by=owner.id,
        name="Source diagram",
        description="Copied diagram",
        diagram_data={"nodes": [{"id": "node-1"}], "edges": []},
        current_version=4,
        snapshot="source-snapshot",
    )
    db.add(diagram)
    db.flush()
    db.add(
        DiagramVersion(
            diagram_id=diagram.id,
            version_number=4,
            diagram_data=diagram.diagram_data,
            name=diagram.name,
            description=diagram.description,
            comment="Source history",
            created_by=owner.id,
        )
    )

    model = Model(
        diagram_id=diagram.id,
        framework_id=framework.id,
        name="Source model",
        status=ModelStatus.completed,
        created_by=owner.id,
    )
    db.add(model)
    db.flush()

    diagram_threat = DiagramThreat(
        diagram_id=diagram.id,
        model_id=model.id,
        threat_id=threat.id,
        element_id="node-1",
        element_type="node",
        status="accepted",
        comments="Source decision",
        likelihood=4,
        impact=3,
        risk_score=12,
        severity="high",
        acceptance_justification="Accepted upstream",
        acceptance_approver_id=owner.id,
        acceptance_review_date=datetime(2026, 1, 5, tzinfo=timezone.utc),
        accepted_at=datetime(2026, 1, 4, tzinfo=timezone.utc),
        acceptance_review_status="approved",
        acceptance_review_note="Approved for source product",
        acceptance_reviewed_at=datetime(2026, 1, 5, tzinfo=timezone.utc),
    )
    db.add(diagram_threat)
    db.flush()
    db.add(DiagramThreatAttackTechnique(
        diagram_threat_id=diagram_threat.id,
        technique_id="T1190",
        created_by=owner.id,
    ))
    db.add(DiagramMitigation(
        diagram_id=diagram.id,
        model_id=model.id,
        mitigation_id=mitigation.id,
        element_id="node-1",
        element_type="node",
        threat_id=diagram_threat.id,
        status="verified",
        comments="Already verified",
    ))
    db.flush()
    return product


def test_duplicate_product_copies_structure_and_resets_workflow(
    client: TestClient,
    standard_user: User,
    user_headers: dict,
    db: Session,
):
    source = _source_product(db, standard_user)

    response = client.post(
        f"/api/products/{source.id}/duplicate",
        json={"name": "Duplicated product"},
        headers=user_headers,
    )

    assert response.status_code == 201
    duplicate_id = response.json()["id"]
    duplicate = db.get(Product, duplicate_id)
    assert duplicate is not None
    assert duplicate.name == "Duplicated product"
    assert duplicate.user_id == standard_user.id
    assert duplicate.description == "Copied description"
    assert duplicate.is_public is False
    assert duplicate.status == "design"
    assert duplicate.jira_project_key is None

    duplicate_diagram = db.query(Diagram).filter_by(product_id=duplicate.id).one()
    assert duplicate_diagram.id != source.diagrams[0].id
    assert duplicate_diagram.diagram_data == source.diagrams[0].diagram_data
    assert duplicate_diagram.diagram_data is not source.diagrams[0].diagram_data
    assert duplicate_diagram.current_version == 0
    assert duplicate_diagram.snapshot is None
    assert db.query(DiagramVersion).filter_by(diagram_id=duplicate_diagram.id).count() == 0

    duplicate_model = db.query(Model).filter_by(diagram_id=duplicate_diagram.id).one()
    assert duplicate_model.status == ModelStatus.in_progress
    assert duplicate_model.completed_at is None

    duplicate_threat = db.query(DiagramThreat).filter_by(diagram_id=duplicate_diagram.id).one()
    assert duplicate_threat.status == "identified"
    assert duplicate_threat.comments is None
    assert duplicate_threat.likelihood is None
    assert duplicate_threat.impact is None
    assert duplicate_threat.risk_score is None
    assert duplicate_threat.severity is None
    assert duplicate_threat.acceptance_justification is None
    assert duplicate_threat.acceptance_approver_id is None
    assert duplicate_threat.acceptance_review_date is None
    assert duplicate_threat.accepted_at is None
    assert duplicate_threat.acceptance_review_status is None
    assert duplicate_threat.acceptance_review_note is None
    assert duplicate_threat.acceptance_reviewed_at is None
    assert db.query(DiagramThreatAttackTechnique).filter_by(
        diagram_threat_id=duplicate_threat.id,
        technique_id="T1190",
    ).count() == 1

    duplicate_mitigation = db.query(DiagramMitigation).filter_by(diagram_id=duplicate_diagram.id).one()
    assert duplicate_mitigation.status == "proposed"
    assert duplicate_mitigation.comments is None
    assert duplicate_mitigation.threat_id == duplicate_threat.id


def test_duplicate_product_requires_edit_permission(
    client: TestClient,
    standard_user: User,
    other_user: User,
    db: Session,
):
    source = _source_product(db, standard_user)

    response = client.post(
        f"/api/products/{source.id}/duplicate",
        json={"name": "Unauthorized copy"},
        headers=make_auth_headers(other_user),
    )

    assert response.status_code == 403


def test_duplicate_product_allows_editor_collaborator(
    client: TestClient,
    standard_user: User,
    other_user: User,
    db: Session,
):
    source = _source_product(db, standard_user)
    db.add(
        ProductCollaborator(
            product_id=source.id,
            user_id=other_user.id,
            role=CollaboratorRole.EDITOR.value,
            added_by=standard_user.id,
        )
    )
    db.flush()

    response = client.post(
        f"/api/products/{source.id}/duplicate",
        json={"name": "Editor copy"},
        headers=make_auth_headers(other_user),
    )

    assert response.status_code == 201
    duplicate = db.get(Product, response.json()["id"])
    assert duplicate is not None
    assert duplicate.user_id == other_user.id
    assert duplicate.is_public is False
    assert duplicate.collaborators == []


def test_duplicate_product_rejects_read_only_owner(
    client: TestClient,
    standard_user: User,
    db: Session,
):
    source = _source_product(db, standard_user)
    standard_user.role = UserRole.READ_ONLY.value
    db.flush()

    response = client.post(
        f"/api/products/{source.id}/duplicate",
        json={"name": "Read-only copy"},
        headers=make_auth_headers(standard_user),
    )

    assert response.status_code == 403
