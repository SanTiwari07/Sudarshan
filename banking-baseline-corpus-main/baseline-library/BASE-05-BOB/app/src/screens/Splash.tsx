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
    <div className="flex flex-col items-center justify-center h-full" style={{ backgroundColor: 'var(--color-primary)' }}>
      <div className="w-24 h-24 rounded-full flex items-center justify-center mb-6" style={{ backgroundColor: 'var(--color-surface)' }}>
        {/* Test mark */}
        <div className="w-12 h-12 rounded-full" style={{ backgroundColor: 'var(--color-primary)' }}></div>
      </div>
      <h1 className="text-3xl font-bold text-white mb-2">bob World</h1>
      <p className="text-white opacity-90">Banking & Experience</p>
    </div>
  );
};
