import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';
import { InputField } from '../components/primitives/InputField';

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    navigate('/mpin');
  };

  return (
    <div style={{ padding: 'var(--space-24)', display: 'flex', flexDirection: 'column', height: '100%', backgroundColor: 'var(--color-surface)' }}>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center', marginBottom: 'var(--space-32)' }}>
          <h1 style={{ color: 'var(--color-primary)', margin: 0, fontSize: '28px', fontWeight: 700 }}>HDFC Bank</h1>
          <p style={{ color: 'var(--color-text-secondary)', marginTop: 'var(--space-8)' }}>Welcome to MobileBanking</p>
        </div>

        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-20)' }}>
          <InputField
            label="Customer ID/Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter your ID"
          />
          <Button type="submit" variant="primary" fullWidth>
            Login
          </Button>
        </form>

        <div style={{ marginTop: 'var(--space-24)', textAlign: 'center' }}>
          <Button variant="secondary" onClick={() => {}} style={{ color: 'var(--color-primary)', fontWeight: 600 }}>
            Forgot?
          </Button>
          <span style={{ margin: '0 var(--space-8)', color: 'var(--color-divider)' }}>|</span>
          <Button variant="secondary" onClick={() => {}} style={{ color: 'var(--color-primary)', fontWeight: 600 }}>
            Register
          </Button>
        </div>
      </div>
    </div>
  );
};
