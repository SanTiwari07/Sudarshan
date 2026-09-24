import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';

export const Services: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div style={{ backgroundColor: 'var(--color-bg)', minHeight: '100%' }}>
      <Header title="Services" showBack onBack={() => navigate('/home')} />
      <div style={{ padding: 'var(--space-16)', textAlign: 'center', marginTop: '40px' }}>
        <h3 style={{ color: 'var(--color-text-primary)' }}>Services (WIP)</h3>
        <p style={{ color: 'var(--color-text-secondary)' }}>This section is currently a placeholder.</p>
      </div>
    </div>
  );
};
