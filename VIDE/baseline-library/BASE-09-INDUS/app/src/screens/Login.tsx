import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';
import { InputField } from '../components/primitives/InputField';

const Login: React.FC = () => {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    if (username) {
      navigate('/mpin');
    }
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      padding: 'var(--space-24)',
      height: '100vh',
      backgroundColor: 'var(--color-background)'
    }}>
      <div style={{ marginTop: 'var(--space-48)', marginBottom: 'var(--space-48)' }}>
        <h1 style={{ color: 'var(--color-primary)', marginBottom: 'var(--space-8)' }}>Welcome Back</h1>
        <p style={{ color: 'var(--color-text-secondary)' }}>Log in to IndusMobile</p>
      </div>

      <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-16)', flex: 1 }}>
        <InputField
          label="Username or Mobile Number"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Enter username"
        />
        
        <Button type="submit" variant="primary" fullWidth disabled={!username}>
          Continue
        </Button>
      </form>
    </div>
  );
};

export default Login;
