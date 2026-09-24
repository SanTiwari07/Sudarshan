import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';
import { InputField } from '../components/primitives/InputField';

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const [userId, setUserId] = useState('');

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    if (userId.trim()) {
      navigate('/mpin');
    }
  };

  return (
    <div style={{ padding: 'var(--spacing-3)', minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <div style={{ marginTop: '20vh', marginBottom: 'var(--spacing-4)', textAlign: 'center' }}>
        <h1 style={{ color: 'var(--color-primary)', marginBottom: 'var(--spacing-1)' }}>Welcome to PNB ONE</h1>
        <p style={{ color: 'var(--color-text-secondary)' }}>Login with your User ID</p>
      </div>

      <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-3)' }}>
        <InputField
          label="User ID"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          placeholder="Enter User ID"
          required
        />
        
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-1)' }}>
            <input type="checkbox" />
            <span style={{ fontSize: '0.875rem' }}>Remember Me</span>
          </label>
          <button type="button" style={{ 
            background: 'none', 
            border: 'none', 
            color: 'var(--color-primary)', 
            fontWeight: 500,
            cursor: 'pointer',
            padding: 0
          }}>
            Trouble Login?
          </button>
        </div>

        <Button 
          type="submit" 
          variant="primary" 
          fullWidth
          disabled={!userId.trim()}
          style={{ marginTop: 'var(--spacing-2)' }}
        >
          Sign In
        </Button>
      </form>
    </div>
  );
};
