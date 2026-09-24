import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const Splash: React.FC = () => {
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
      alignItems: 'center',
      justifyContent: 'center',
      height: '100vh',
      backgroundColor: 'var(--color-primary)',
      color: 'var(--color-surface)'
    }}>
      <h1>IndusMobile</h1>
      <p style={{ marginTop: 'var(--space-8)' }}>Digital Banking</p>
    </div>
  );
};

export default Splash;
