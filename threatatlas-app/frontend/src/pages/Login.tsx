import { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Network, AlertCircle, Loader2, KeyRound } from 'lucide-react';
import { authApi, oidcLoginUrl, type LDAPProviderInfo, type OIDCProviderInfo } from '@/lib/api';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [ldapUsername, setLdapUsername] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [oidcProviders, setOidcProviders] = useState<OIDCProviderInfo[]>([]);
  const [ldapProviders, setLdapProviders] = useState<LDAPProviderInfo[]>([]);
  const [selectedLdap, setSelectedLdap] = useState<LDAPProviderInfo | null>(null);
  const { login, loginWithToken } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  useEffect(() => {
    const callbackError = searchParams.get('error');
    if (callbackError) {
      setError(`Single sign-on failed: ${callbackError}`);
    }

    Promise.allSettled([authApi.listOidcProviders(), authApi.listLdapProviders()]).then(([oidc, ldap]) => {
      setOidcProviders(oidc.status === 'fulfilled' ? oidc.value.data : []);
      setLdapProviders(ldap.status === 'fulfilled' ? ldap.value.data : []);
    });
  }, [searchParams]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (selectedLdap) {
        const response = await authApi.loginLdap(selectedLdap.name, ldapUsername, password);
        await loginWithToken(response.data.access_token);
      } else {
        await login(email, password);
      }
      navigate('/');
    } catch (err: unknown) {
      const detail = axios.isAxiosError(err) ? err.response?.data?.detail : null;
      setError(typeof detail === 'string' ? detail : 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleSsoLogin = (provider: OIDCProviderInfo) => {
    window.location.href = oidcLoginUrl(provider.login_url);
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-linear-to-br from-background via-muted/40 to-background">
      <Card className="animate-fadeInUp w-full max-w-lg shadow-lg border-border/60 rounded-2xl">
        <CardHeader className="space-y-2 text-center pt-8 pb-6">
          <div className="flex justify-center mb-4">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-linear-to-br from-primary to-primary/80 text-primary-foreground shadow-lg">
              <Network className="h-8 w-8" />
            </div>
          </div>
          <CardTitle className="text-4xl font-extrabold tracking-tight">OWASP ThreatAtlas</CardTitle>
          <CardDescription className="text-base">Sign in to your account to continue</CardDescription>
        </CardHeader>
        <CardContent className="pb-8">
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="login-identifier" className="text-sm font-semibold">
                {selectedLdap ? 'Directory username' : 'Email'}
              </Label>
              <Input
                id="login-identifier"
                type={selectedLdap ? 'text' : 'email'}
                value={selectedLdap ? ldapUsername : email}
                onChange={(e) => selectedLdap ? setLdapUsername(e.target.value) : setEmail(e.target.value)}
                placeholder={selectedLdap ? 'e.g. jdoe' : 'you@example.com'}
                required
                disabled={loading}
                className="h-11 rounded-lg border-border/60"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password" className="text-sm font-semibold">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                required
                disabled={loading}
                className="h-11 rounded-lg border-border/60"
              />
            </div>
            {error && (
              <div className="flex items-center gap-2.5 text-sm text-destructive bg-destructive/10 p-3.5 rounded-lg border border-destructive/20 animate-fadeIn">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
            <Button type="submit" className="w-full h-11 shadow-md hover:shadow-lg transition-all" disabled={loading}>
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Signing in...
                </>
              ) : (
                selectedLdap ? `Sign in with ${selectedLdap.display_name}` : 'Sign In'
              )}
            </Button>
          </form>

          {(oidcProviders.length > 0 || ldapProviders.length > 0) && (
            <div className="mt-6 space-y-3">
              <div className="relative flex items-center">
                <div className="flex-grow border-t border-border/60" />
                <span className="mx-3 text-xs uppercase tracking-wider text-muted-foreground">or continue with</span>
                <div className="flex-grow border-t border-border/60" />
              </div>
              <div className="grid gap-2">
                {selectedLdap && (
                  <Button
                    type="button"
                    variant="outline"
                    className="w-full h-11 rounded-lg justify-center gap-2"
                    onClick={() => { setSelectedLdap(null); setError(''); }}
                    disabled={loading}
                  >
                    Local account
                  </Button>
                )}
                {ldapProviders.map((provider) => (
                  <Button
                    key={`ldap-${provider.name}`}
                    type="button"
                    variant={selectedLdap?.name === provider.name ? 'default' : 'outline'}
                    className="w-full h-11 rounded-lg justify-center gap-2"
                    onClick={() => { setSelectedLdap(provider); setError(''); }}
                    disabled={loading}
                  >
                    <Network className="h-4 w-4" />
                    {provider.display_name}
                  </Button>
                ))}
                {oidcProviders.map((provider) => (
                  <Button
                    key={provider.name}
                    type="button"
                    variant="outline"
                    className="w-full h-11 rounded-lg justify-center gap-2"
                    onClick={() => handleSsoLogin(provider)}
                    disabled={loading}
                  >
                    <KeyRound className="h-4 w-4" />
                    {provider.display_name}
                  </Button>
                ))}
              </div>
            </div>
          )}

          <div className="mt-6 text-center text-sm">
            <p className="text-muted-foreground">
              Don't have an account? Contact your administrator for an invitation.
            </p>
          </div>
        </CardContent>
      </Card>
      <div className="absolute bottom-4 left-0 right-0 text-center text-xs">
        The project link is <a href="https://owasp.org/www-project-threatatlas/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline font-semibold transition-all">OWASP ThreatAtlas</a>
      </div>
    </div>
  );
}
