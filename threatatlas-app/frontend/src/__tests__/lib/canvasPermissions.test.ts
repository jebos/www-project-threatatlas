import { describe, expect, it } from 'vitest';
import type { Edge, EdgeChange, Node, NodeChange } from '@xyflow/react';
import {
  filterEdgeChangesForPermission,
  filterNodeChangesForPermission,
} from '@/lib/canvasPermissions';

describe('canvas edit permissions', () => {
  it('keeps all node changes for editors', () => {
    const changes: NodeChange<Node>[] = [
      { type: 'select', id: 'node-1', selected: true },
      { type: 'position', id: 'node-1', position: { x: 10, y: 20 }, dragging: true },
      { type: 'remove', id: 'node-2' },
    ];

    expect(filterNodeChangesForPermission(changes, true)).toEqual(changes);
  });

  it('allows viewer selection and measurement but rejects node mutations', () => {
    const changes: NodeChange<Node>[] = [
      { type: 'select', id: 'node-1', selected: true },
      { type: 'dimensions', id: 'node-1', dimensions: { width: 100, height: 50 } },
      { type: 'position', id: 'node-1', position: { x: 10, y: 20 }, dragging: true },
      { type: 'remove', id: 'node-2' },
    ];

    expect(filterNodeChangesForPermission(changes, false).map(change => change.type)).toEqual([
      'select',
      'dimensions',
    ]);
  });

  it('allows viewer edge selection but rejects edge mutations', () => {
    const changes: EdgeChange<Edge>[] = [
      { type: 'select', id: 'edge-1', selected: true },
      { type: 'remove', id: 'edge-1' },
    ];

    expect(filterEdgeChangesForPermission(changes, false)).toEqual([changes[0]]);
  });
});
