import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';
import { InputField } from '../components/primitives/InputField';

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const [userId, setUserId] = useState('');

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    navigate('/mpin');
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      backgroundColor: 'var(--color-surface)',
      padding: 'var(--spacing-3)',
    }}>
      <div style={{
        marginTop: '80px',
        marginBottom: 'var(--spacing-4)',
        textAlign: 'center'
      }}>
        <h1 style={{ color: 'var(--color-primary)' }}>Welcome to iMobile Pay</h1>
        <p style={{ color: 'var(--color-text-secondary)', marginTop: 'var(--spacing-1)' }}>
          Please log in to continue
        </p>
      </div>

      <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-3)' }}>
        <InputField
          label="User ID"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          placeholder="Enter User ID"
          required
        />
        <Button type="submit" variant="primary" style={{ backgroundColor: 'var(--color-secondary)' }}>
          Login
        </Button>
      </form>

      <div style={{
        marginTop: 'auto',
        marginBottom: 'var(--spacing-4)',
        display: 'flex',
        justifyContent: 'space-between'
      }}>
        <Button variant="outline" onClick={() => {}} style={{ border: 'none', color: 'var(--color-primary)' }}>
          Forgot User ID?
        </Button>
        <Button variant="outline" onClick={() => {}} style={{ border: 'none', color: 'var(--color-primary)' }}>
          Register
        </Button>
      </div>
    </div>
  );
};
