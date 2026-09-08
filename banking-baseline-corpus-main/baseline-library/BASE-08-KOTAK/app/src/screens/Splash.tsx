import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const Splash: React.FC = () => {
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setTimeout(() => {
      navigate('/login');
    }, 2000); // 2 second mock delay
    return () => clearTimeout(timer);
  }, [navigate]);

  return (
    <div className="flex flex-col items-center justify-center min-h-screen" style={{ backgroundColor: 'var(--color-primary)' }}>
      <div className="flex flex-col items-center">
        {/* Placeholder for Kotak 811 logo */}
        <div className="w-24 h-24 rounded-full flex items-center justify-center mb-4" style={{ backgroundColor: 'var(--color-surface)', color: 'var(--color-primary)' }}>
          <span className="font-bold text-2xl">811</span>
        </div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--color-surface)' }}>
          Kotak Mahindra Bank
        </h1>
      </div>
    </div>
  );
};

export default Splash;
