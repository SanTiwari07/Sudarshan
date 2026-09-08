import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Splash.css';

export default function Splash() {
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setTimeout(() => {
      navigate('/login');
    }, 2000);
    return () => clearTimeout(timer);
  }, [navigate]);

  return (
    <div className="splash-screen">
      <div className="splash-logo">
        <div className="axis-mark">
          <span className="axis-text">AXIS</span>
          <div className="axis-accent"></div>
        </div>
        <p className="open-brand">open by Axis Bank</p>
      </div>
    </div>
  );
}
