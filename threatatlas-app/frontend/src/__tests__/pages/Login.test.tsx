import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import Login from '@/pages/Login';

const mocks = vi.hoisted(() => ({
  login: vi.fn(),
  loginWithToken: vi.fn(),
  listOidcProviders: vi.fn(),
  listLdapProviders: vi.fn(),
  loginLdap: vi.fn(),
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ login: mocks.login, loginWithToken: mocks.loginWithToken }),
}));

vi.mock('@/lib/api', () => ({
  authApi: {
    listOidcProviders: mocks.listOidcProviders,
    listLdapProviders: mocks.listLdapProviders,
    loginLdap: mocks.loginLdap,
  },
  oidcLoginUrl: (path: string) => path,
}));

function renderLogin() {
  return render(<MemoryRouter><Login /></MemoryRouter>);
}

describe('LDAP login', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.listOidcProviders.mockResolvedValue({ data: [] });
    mocks.listLdapProviders.mockResolvedValue({
      data: [{ name: 'corp', display_name: 'Corporate Directory' }],
    });
    mocks.loginLdap.mockResolvedValue({ data: { access_token: 'ldap-token', token_type: 'bearer' } });
    mocks.loginWithToken.mockResolvedValue(undefined);
  });

  it('authenticates with the selected LDAP provider', async () => {
    renderLogin();
    const providerButton = await screen.findByRole('button', { name: 'Corporate Directory' });
    fireEvent.click(providerButton);
    fireEvent.change(screen.getByLabelText('Directory username'), { target: { value: 'alice' } });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'Directory-Password1!' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in with Corporate Directory' }));

    await waitFor(() => {
      expect(mocks.loginLdap).toHaveBeenCalledWith('corp', 'alice', 'Directory-Password1!');
      expect(mocks.loginWithToken).toHaveBeenCalledWith('ldap-token');
    });
  });
});
