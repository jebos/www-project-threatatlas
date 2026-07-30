import { describe, expect, it } from 'vitest';
import {
  API_BASE_URL,
  api,
  oidcLoginUrl,
  resolveApiBaseUrl,
  resolveWebSocketBaseUrl,
} from '@/lib/api';

describe('API client configuration', () => {
  it('uses the browser origin for packaged deployments without an API URL', () => {
    expect(resolveApiBaseUrl(undefined, false, 'https://threatatlas.example')).toBe(
      'https://threatatlas.example',
    );
  });

  it('keeps an explicitly configured API origin and removes trailing slashes', () => {
    expect(resolveApiBaseUrl('https://api.example///', false, 'https://threatatlas.example')).toBe(
      'https://api.example',
    );
  });

  it('treats a proxied API path as same-origin', () => {
    expect(resolveApiBaseUrl('/api', false, 'https://threatatlas.example')).toBe(
      'https://threatatlas.example',
    );
  });

  it('keeps the local backend default for Vite development', () => {
    expect(resolveApiBaseUrl(undefined, true, 'http://localhost:5173')).toBe(
      'http://localhost:8000',
    );
  });

  it('keeps slashless endpoint paths unchanged', () => {
    expect(api.getUri({ url: '/auth/login' })).toBe(`${api.defaults.baseURL}/auth/login`);
  });

  it('builds OIDC login redirects from the resolved API origin', () => {
    expect(oidcLoginUrl('/api/auth/oidc/example/login')).toBe(
      `${API_BASE_URL}/api/auth/oidc/example/login`,
    );
  });

  it('derives secure and non-secure WebSocket origins from the API origin', () => {
    expect(resolveWebSocketBaseUrl('https://threatatlas.example')).toBe(
      'wss://threatatlas.example',
    );
    expect(resolveWebSocketBaseUrl('http://localhost:8000')).toBe('ws://localhost:8000');
  });
});
