import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export const Splash: React.FC = () => {
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setTimeout(() => {
      navigate('/login');
    }, 2000);
    return () => clearTimeout(timer);
  }, [navigate]);

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'center',
      alignItems: 'center',
      height: '100vh',
      backgroundColor: 'var(--color-primary)',
      color: 'var(--color-surface)',
    }}>
      <h1 style={{ fontSize: '3rem', fontWeight: 'bold' }}>iMobile</h1>
      <p style={{ marginTop: 'var(--spacing-2)', opacity: 0.8 }}>Pay</p>
    </div>
  );
};
