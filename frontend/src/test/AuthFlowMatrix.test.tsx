import { describe, test, expect, beforeEach, vi, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import App from '../App';
import { isTokenValid, parseJwt } from '../context/AuthContext';
import { handle401Response } from '../config';

// Helper to construct mock JWT tokens
function createMockJwt(payload: object): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const encodedPayload = btoa(JSON.stringify(payload))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  const signature = 'mock_signature';
  return `${header}.${encodedPayload}.${signature}`;
}

const VALID_TOKEN = createMockJwt({
  sub: 'test_analyst',
  role: 'analyst',
  exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour in future
});

const EXPIRED_TOKEN = createMockJwt({
  sub: 'test_analyst',
  role: 'analyst',
  exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour in past
});

describe('SUDARSHAN Authentication & Routing Flow Test Matrix (20/20)', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  // ---------------------------------------------------------------------------
  // TEST 1 - Fresh Browser (cleared token -> /login, Upload never appears)
  // ---------------------------------------------------------------------------
  test('TEST 1: Fresh Browser - cleared token redirects to /login and Upload never mounts', async () => {
    localStorage.clear();

    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });

    expect(screen.queryByText(/Upload APK/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Drop APK file here/i)).not.toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // TEST 2 - Login (valid credentials -> JWT -> / -> Upload)
  // ---------------------------------------------------------------------------
  test('TEST 2: Login - valid credentials stores JWT, updates auth state and lands on Upload page', async () => {
    const mockResponse = {
      access_token: VALID_TOKEN,
      username: 'analyst_bob',
      role: 'analyst',
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockResponse,
    } as Response);

    render(
      <MemoryRouter initialEntries={['/login']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByPlaceholderText('analyst_name')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByPlaceholderText('analyst_name'), {
      target: { value: 'analyst_bob' },
    });
    fireEvent.change(screen.getByPlaceholderText('••••••••'), {
      target: { value: 'SecretPassword123' },
    });

    fireEvent.click(screen.getByRole('button', { name: /Sign In/i }));

    await waitFor(() => {
      expect(localStorage.getItem('sudarshan_token')).toBe(VALID_TOKEN);
      expect(localStorage.getItem('sudarshan_user')).toBe('analyst_bob');
    });

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 3 - Invalid Credentials (invalid creds -> stay on /login)
  // ---------------------------------------------------------------------------
  test('TEST 3: Invalid Credentials - failed login stays on /login with error message', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ detail: 'Incorrect username or password' }),
    } as Response);

    render(
      <MemoryRouter initialEntries={['/login']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByPlaceholderText('analyst_name')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByPlaceholderText('analyst_name'), {
      target: { value: 'wrong_user' },
    });
    fireEvent.change(screen.getByPlaceholderText('••••••••'), {
      target: { value: 'wrong_password' },
    });

    fireEvent.click(screen.getByRole('button', { name: /Sign In/i }));

    await waitFor(() => {
      expect(screen.getByText('Incorrect username or password')).toBeInTheDocument();
    });

    expect(localStorage.getItem('sudarshan_token')).toBeNull();
    expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // TEST 4 - Direct Root Access (unauth / -> /login)
  // ---------------------------------------------------------------------------
  test('TEST 4: Direct Root Access - unauthenticated user accessing / is redirected to /login', async () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });

    expect(screen.queryByText(/Select APK file or drop here/i)).not.toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // TEST 5 - Technical View (unauth /technical -> /login)
  // ---------------------------------------------------------------------------
  test('TEST 5: Technical View - unauthenticated access to /technical redirects to /login', async () => {
    render(
      <MemoryRouter initialEntries={['/technical']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 6 - Threat Intelligence (unauth /threat-intel -> /login)
  // ---------------------------------------------------------------------------
  test('TEST 6: Threat Intelligence - unauthenticated access to /threat-intel redirects to /login', async () => {
    render(
      <MemoryRouter initialEntries={['/threat-intel']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 7 - Cases (unauth /history -> /login)
  // ---------------------------------------------------------------------------
  test('TEST 7: Cases - unauthenticated access to /history redirects to /login', async () => {
    render(
      <MemoryRouter initialEntries={['/history']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 8 - AI Assistant (unauth /chat -> /login)
  // ---------------------------------------------------------------------------
  test('TEST 8: AI Assistant - unauthenticated access to /chat redirects to /login', async () => {
    render(
      <MemoryRouter initialEntries={['/chat']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 9 - Deep Link (unauth /history/:sha256 -> /login)
  // ---------------------------------------------------------------------------
  test('TEST 9: Deep Link - unauthenticated access to /history/:sha256 redirects to /login', async () => {
    const dummyHash = 'a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890';
    render(
      <MemoryRouter initialEntries={[`/history/${dummyHash}`]}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 10 - Authenticated Deep Link (auth /history/:sha256 -> InvestigationShell -> Case)
  // ---------------------------------------------------------------------------
  test('TEST 10: Authenticated Deep Link - auth user opening /history/:sha renders InvestigationShell and restores case', async () => {
    localStorage.setItem('sudarshan_token', VALID_TOKEN);
    localStorage.setItem('sudarshan_user', 'test_analyst');
    localStorage.setItem('sudarshan_role', 'analyst');

    const sampleHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes(`/cases/${sampleHash}`) || url.includes(`/status/`)) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            status: 'done',
            result: {
              sha256: sampleHash,
              package_name: 'com.bank.fake.app',
              app_name: 'Fake Bank App',
              analysis_mode: 'static',
              base_score: 85,
              ai_confidence_multiplier: 1.0,
              final_risk_score: 85,
              risk_band: 'CRITICAL',
              confidence: 90,
              recommended_action: 'Block immediately',
              manifest_findings: [],
              code_findings: [],
              dangerous_permissions: [],
              activities: [],
              services: [],
              receivers: [],
              certificate: {},
              domains: {},
              hardcoded_secrets: [],
              all_permissions: [],
              hardcoded_urls_ips: [],
              targets_indian_banks: true,
              has_accessibility_abuse: true,
              has_sms_read_write: false,
              has_system_alert_window: false,
              dynamic_available: false,
              executive_view: {
                risk_badge: 'CRITICAL',
                plain_english_narrative: 'Deep link case restored.',
                recommended_actions: ['Block app'],
                customer_advisory_draft: 'Advisory draft',
              },
              technical_view: {
                permissions_fired: [],
                strings_fired: [],
                apis_fired: [],
                matched_rule: 'rule_1',
                decoded_manifest_excerpts: [],
              },
            },
          }),
        } as Response);
      }
      return Promise.resolve({ ok: true, json: async () => ({}) } as Response);
    });

    render(
      <MemoryRouter initialEntries={[`/history/${sampleHash}`]}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 11 - Authenticated /login (auth opening /login -> /)
  // ---------------------------------------------------------------------------
  test('TEST 11: Authenticated /login - authenticated user attempting to open /login is redirected to /', async () => {
    localStorage.setItem('sudarshan_token', VALID_TOKEN);
    localStorage.setItem('sudarshan_user', 'test_analyst');
    localStorage.setItem('sudarshan_role', 'analyst');

    render(
      <MemoryRouter initialEntries={['/login']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument();
    });
    expect(screen.queryByRole('heading', { name: /^sign in$/i })).not.toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // TEST 12 - Refresh (auth refresh -> remain auth)
  // ---------------------------------------------------------------------------
  test('TEST 12: Refresh - authenticated state persists across page refresh', async () => {
    localStorage.setItem('sudarshan_token', VALID_TOKEN);
    localStorage.setItem('sudarshan_user', 'persisted_user');
    localStorage.setItem('sudarshan_role', 'analyst');

    const { unmount } = render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument();
    });

    unmount();

    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 13 - Logout (logout -> token removed -> /login)
  // ---------------------------------------------------------------------------
  test('TEST 13: Logout - clicking Logout removes token and redirects to /login', async () => {
    localStorage.setItem('sudarshan_token', VALID_TOKEN);
    localStorage.setItem('sudarshan_user', 'active_analyst');

    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument();
    });

    const logoutBtn = screen.getByRole('button', { name: /sign out/i });
    fireEvent.click(logoutBtn);

    await waitFor(() => {
      expect(localStorage.getItem('sudarshan_token')).toBeNull();
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 14 - Access After Logout (unauth / -> /login)
  // ---------------------------------------------------------------------------
  test('TEST 14: Access After Logout - subsequent navigation after logout redirects to /login', async () => {
    localStorage.setItem('sudarshan_token', VALID_TOKEN);

    const { unmount } = render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /sign out/i }));

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });

    unmount();

    render(
      <MemoryRouter initialEntries={['/technical']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 15 - Invalid Token (invalid/expired JWT -> rejected -> cleared -> /login)
  // ---------------------------------------------------------------------------
  test('TEST 15: Invalid Token - expired or malformed token in localStorage is automatically cleared on init', async () => {
    localStorage.setItem('sudarshan_token', EXPIRED_TOKEN);
    localStorage.setItem('sudarshan_user', 'expired_user');

    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(localStorage.getItem('sudarshan_token')).toBeNull();
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });
  });

  test('TEST 15b: Invalid Token - 401 API response triggers global handle401 and clears auth', async () => {
    localStorage.setItem('sudarshan_token', VALID_TOKEN);

    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument();
    });

    handle401Response();

    await waitFor(() => {
      expect(localStorage.getItem('sudarshan_token')).toBeNull();
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 16 - No Protected Content Flash (no Upload UI / sidebar / data flash before auth redirect)
  // ---------------------------------------------------------------------------
  test('TEST 16: No Protected Content Flash - unauthenticated users see no protected UI elements before redirect', () => {
    localStorage.clear();

    const { container } = render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    );

    expect(container.querySelector('aside')).toBeNull();
    expect(screen.queryByRole('button', { name: /sign out/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/Select APK file or drop here/i)).not.toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // TEST 17 - Existing Upload Flow (functional after login)
  // ---------------------------------------------------------------------------
  test('TEST 17: Existing Upload Flow - authenticated user can access upload interface and drop zone', async () => {
    localStorage.setItem('sudarshan_token', VALID_TOKEN);

    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 18 - Website URL Flow (functional after login)
  // ---------------------------------------------------------------------------
  test('TEST 18: Website URL Flow - website discovery panel is present and functional when authenticated', async () => {
    localStorage.setItem('sudarshan_token', VALID_TOKEN);

    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 19 - Sidebar (unauth: hidden; auth: visible)
  // ---------------------------------------------------------------------------
  test('TEST 19: Sidebar - sidebar is hidden when unauthenticated and visible when authenticated', async () => {
    const { unmount, container } = render(
      <MemoryRouter initialEntries={['/login']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });
    expect(container.querySelector('aside')).toBeNull();

    unmount();

    localStorage.setItem('sudarshan_token', VALID_TOKEN);
    localStorage.setItem('sudarshan_user', 'active_analyst');

    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('complementary', { name: /Sidebar Navigation/i })).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 20 - Browser Back Button (back after logout -> protected page not accessible)
  // ---------------------------------------------------------------------------
  test('TEST 20: Browser Back Button - navigating back to protected page after logout immediately bounces to /login', async () => {
    localStorage.setItem('sudarshan_token', VALID_TOKEN);

    const { unmount } = render(
      <MemoryRouter initialEntries={['/history']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /sign out/i }));

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });

    unmount();

    render(
      <MemoryRouter initialEntries={['/history']}>
        <App />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^sign in$/i })).toBeInTheDocument();
    });
  });
});

