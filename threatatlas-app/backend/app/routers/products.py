from copy import deepcopy

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    Diagram as DiagramModel,
    DiagramMitigation as DiagramMitigationModel,
    DiagramThreat as DiagramThreatModel,
    DiagramThreatAttackTechnique,
    Model as ModelModel,
    Product as ProductModel,
    User as UserModel,
)
from app.models.enums import UserRole
from app.models.model import ModelStatus
from app.schemas import Product, ProductCreate, ProductDuplicate, ProductUpdate
from app.auth.dependencies import get_current_user
from app.auth.permissions import require_standard_or_admin, can_access_product, can_edit_product, PermissionDenied
from app.services.audit import log_event

router = APIRouter(prefix="/products", tags=["products"])


def _product_response(product: ProductModel, user: UserModel) -> Product:
    """Serialize a product with the caller's effective edit permission."""
    return Product.model_validate(product).model_copy(
        update={"can_edit": can_edit_product(user, product)}
    )


@router.get("", response_model=list[Product])
def list_products(
    current_user: UserModel = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    List products.

    Admin users see all products.
    Standard and read-only users see their own products and products they collaborate on.
    """
    from sqlalchemy import or_
    from app.models import ProductCollaborator

    query = db.query(ProductModel)

    # Admins see all products
    # Others see products they own or collaborate on
    if current_user.role != UserRole.ADMIN.value:
        query = query.outerjoin(ProductCollaborator).filter(
            or_(
                ProductModel.user_id == current_user.id,
                ProductCollaborator.user_id == current_user.id,
                ProductModel.is_public.is_(True)
            )
        ).distinct()

    products = query.offset(skip).limit(limit).all()
    return [_product_response(product, current_user) for product in products]


@router.get("/{product_id}", response_model=Product)
def get_product(
    product_id: int,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a product by ID.

    Admin users can access any product.
    Other users can access their own products and products they collaborate on.
    """
    from sqlalchemy.orm import joinedload

    product = db.query(ProductModel).options(
        joinedload(ProductModel.collaborators)
    ).filter(ProductModel.id == product_id).first()

    if not product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product with id {product_id} not found"
        )

    # Check access (owner, collaborator, or admin)
    if not can_access_product(current_user, product):
        raise PermissionDenied("Not authorized to access this product")

    return _product_response(product, current_user)


@router.post("", response_model=Product, status_code=status.HTTP_201_CREATED)
def create_product(
    product: ProductCreate,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a new product.

    Requires standard or admin role (read-only users cannot create).
    """
    require_standard_or_admin(current_user)

    db_product = ProductModel(
        **product.model_dump(),
        user_id=current_user.id
    )
    db.add(db_product)
    db.commit()
    db.refresh(db_product)
    return _product_response(db_product, current_user)


@router.post("/{product_id}/duplicate", response_model=Product, status_code=status.HTTP_201_CREATED)
def duplicate_product(
    product_id: int,
    payload: ProductDuplicate,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create an independent product copy with a fresh security workflow."""
    require_standard_or_admin(current_user)

    source = db.query(ProductModel).filter(ProductModel.id == product_id).first()
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product with id {product_id} not found",
        )
    if not can_edit_product(current_user, source):
        raise PermissionDenied("Not authorized to duplicate this product")

    duplicate = ProductModel(
        user_id=current_user.id,
        name=payload.name,
        description=source.description,
        # A copy must not become externally visible or reuse the source Jira project.
        is_public=False,
        status="design",
        repository_url=source.repository_url,
        confluence_url=source.confluence_url,
        application_url=source.application_url,
        business_area=source.business_area,
        owner_name=source.owner_name,
        owner_email=source.owner_email,
        jira_project_key=None,
        reviewer=source.reviewer,
        contributors=source.contributors,
    )
    db.add(duplicate)
    db.flush()

    for source_diagram in source.diagrams:
        duplicate_diagram = DiagramModel(
            product_id=duplicate.id,
            created_by=current_user.id,
            name=source_diagram.name,
            description=source_diagram.description,
            diagram_data=deepcopy(source_diagram.diagram_data),
            current_version=0,
            auto_version=source_diagram.auto_version,
            snapshot=None,
        )
        db.add(duplicate_diagram)
        db.flush()

        model_ids: dict[int, int] = {}
        source_models = (
            db.query(ModelModel)
            .filter(ModelModel.diagram_id == source_diagram.id)
            .order_by(ModelModel.id)
            .all()
        )
        for source_model in source_models:
            duplicate_model = ModelModel(
                diagram_id=duplicate_diagram.id,
                framework_id=source_model.framework_id,
                name=source_model.name,
                description=source_model.description,
                status=ModelStatus.in_progress,
                created_by=current_user.id,
                completed_at=None,
            )
            db.add(duplicate_model)
            db.flush()
            model_ids[source_model.id] = duplicate_model.id

        threat_ids: dict[int, int] = {}
        source_threats = (
            db.query(DiagramThreatModel)
            .filter(DiagramThreatModel.diagram_id == source_diagram.id)
            .order_by(DiagramThreatModel.id)
            .all()
        )
        for source_threat in source_threats:
            duplicate_threat = DiagramThreatModel(
                diagram_id=duplicate_diagram.id,
                model_id=model_ids[source_threat.model_id],
                threat_id=source_threat.threat_id,
                element_id=source_threat.element_id,
                element_type=source_threat.element_type,
                status="identified",
                comments=None,
                likelihood=None,
                impact=None,
                risk_score=None,
                severity=None,
                acceptance_justification=None,
                acceptance_approver_id=None,
                acceptance_review_date=None,
                accepted_at=None,
                acceptance_review_status=None,
                acceptance_review_note=None,
                acceptance_reviewed_at=None,
            )
            db.add(duplicate_threat)
            db.flush()
            threat_ids[source_threat.id] = duplicate_threat.id

            techniques = (
                db.query(DiagramThreatAttackTechnique)
                .filter(DiagramThreatAttackTechnique.diagram_threat_id == source_threat.id)
                .all()
            )
            for technique in techniques:
                db.add(
                    DiagramThreatAttackTechnique(
                        diagram_threat_id=duplicate_threat.id,
                        technique_id=technique.technique_id,
                        created_by=current_user.id,
                    )
                )

        source_mitigations = (
            db.query(DiagramMitigationModel)
            .filter(DiagramMitigationModel.diagram_id == source_diagram.id)
            .order_by(DiagramMitigationModel.id)
            .all()
        )
        for source_mitigation in source_mitigations:
            db.add(
                DiagramMitigationModel(
                    diagram_id=duplicate_diagram.id,
                    model_id=model_ids[source_mitigation.model_id],
                    mitigation_id=source_mitigation.mitigation_id,
                    element_id=source_mitigation.element_id,
                    element_type=source_mitigation.element_type,
                    threat_id=threat_ids.get(source_mitigation.threat_id),
                    status="proposed",
                    comments=None,
                )
            )

    log_event(
        db,
        action="product_duplicated",
        entity_type="product",
        entity_name=duplicate.name,
        details={"source_product_id": source.id},
        product_id=duplicate.id,
        user_id=current_user.id,
    )
    db.commit()
    db.refresh(duplicate)
    return _product_response(duplicate, current_user)


@router.put("/{product_id}", response_model=Product)
def update_product(
    product_id: int,
    product: ProductUpdate,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update a product.

    Admin users can update any product.
    Product owners and editor/owner collaborators can update.
    """
    from sqlalchemy.orm import joinedload

    db_product = db.query(ProductModel).options(
        joinedload(ProductModel.collaborators)
    ).filter(ProductModel.id == product_id).first()

    if not db_product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product with id {product_id} not found"
        )

    # Check edit permission (owner, editor/owner collaborator, or admin)
    if not can_edit_product(current_user, db_product):
        raise PermissionDenied("Not authorized to edit this product")

    update_data = product.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_product, field, value)

    db.commit()
    db.refresh(db_product)
    return _product_response(db_product, current_user)


@router.delete("/{product_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_product(
    product_id: int,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a product.

    Only product owner or admin can delete products.
    Collaborators cannot delete, even with owner role.
    """
    from sqlalchemy.orm import joinedload

    db_product = db.query(ProductModel).options(
        joinedload(ProductModel.collaborators)
    ).filter(ProductModel.id == product_id).first()

    if not db_product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product with id {product_id} not found"
        )

    # Only product owner or admin can delete
    if current_user.role != UserRole.ADMIN.value and db_product.user_id != current_user.id:
        raise PermissionDenied("Only product owner can delete products")

    db.delete(db_product)
    db.commit()
    return None
