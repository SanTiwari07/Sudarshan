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
      alignItems: 'center',
      justifyContent: 'center',
      height: '100%',
      backgroundColor: 'var(--color-primary)',
      color: 'white',
      flexDirection: 'column'
    }}>
      <div style={{
        width: '80px',
        height: '80px',
        backgroundColor: 'var(--color-surface)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        marginBottom: '16px'
      }}>
        <div style={{
          width: '40px',
          height: '40px',
          backgroundColor: 'var(--color-primary)'
        }}>
          <div style={{
            width: '100%',
            height: '20px',
            backgroundColor: 'var(--color-secondary)',
            marginTop: '10px'
          }}></div>
        </div>
      </div>
      <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 600 }}>HDFC Bank</h1>
    </div>
  );
};
