import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Building2 } from 'lucide-react';
import './Splash.css';

export const Splash: React.FC = () => {
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setTimeout(() => {
      navigate('/login');
    }, 2000);
    return () => clearTimeout(timer);
  }, [navigate]);

  return (
    <div className="splash-screen">
      <div className="logo-container">
        <div className="logo-mark">
          <Building2 size={64} className="logo-icon" />
          <div className="star-accent"></div>
        </div>
        <h1 className="app-title">BOI Mobile</h1>
        <p className="app-subtitle">Omni Neo Bank App</p>
      </div>
    </div>
  );
};
