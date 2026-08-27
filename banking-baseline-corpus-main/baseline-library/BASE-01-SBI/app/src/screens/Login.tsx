import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';
import { InputField } from '../components/primitives/InputField';

export const Login: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <div style={{ flex: 1 }}>
        <h1 style={{ color: 'var(--color-primary)', textAlign: 'center', marginBottom: '32px' }}>YONO SBI</h1>
        <InputField label="Username" placeholder="Enter username" />
        <InputField label="Password" type="password" placeholder="Enter password" />
        <div style={{ marginTop: '24px' }}>
          <Button fullWidth onClick={() => navigate('/mpin')}>Login</Button>
        </div>
      </div>
      <div style={{ textAlign: 'center' }}>
        <Button variant="secondary" fullWidth onClick={() => {}}>Forgot MPIN?</Button>
        <p style={{ marginTop: '16px', color: 'var(--color-text-secondary)' }}>New user? Register</p>
      </div>
    </div>
  );
};
