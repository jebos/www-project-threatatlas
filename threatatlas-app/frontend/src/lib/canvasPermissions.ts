import type { Edge, EdgeChange, Node, NodeChange } from '@xyflow/react';

export function filterNodeChangesForPermission(
  changes: NodeChange<Node>[],
  canEdit: boolean,
): NodeChange<Node>[] {
  if (canEdit) return changes;
  return changes.filter(change => change.type === 'select' || change.type === 'dimensions');
}

export function filterEdgeChangesForPermission(
  changes: EdgeChange<Edge>[],
  canEdit: boolean,
): EdgeChange<Edge>[] {
  if (canEdit) return changes;
  return changes.filter(change => change.type === 'select');
}
