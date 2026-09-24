import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Splash.css';

export function Splash() {
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setTimeout(() => {
      navigate('/login');
    }, 2000);
    return () => clearTimeout(timer);
  }, [navigate]);

  return (
    <div className="union-splash" data-testid="UNION-SPLASH">
      <div className="union-splash-content">
        <h1>Vyom</h1>
        <p>Union Bank of India</p>
      </div>
    </div>
  );
}
