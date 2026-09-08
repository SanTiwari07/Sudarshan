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
      color: 'var(--color-surface)'
    }}>
      <h1 style={{ fontSize: '2rem', marginBottom: '8px' }}>PNB ONE</h1>
      <p style={{ opacity: 0.8 }}>The all-in-one banking app</p>
    </div>
  );
};
