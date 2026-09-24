import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { PINPad } from '../components/primitives/PINPad';
import './MPIN.css';

export function MPIN() {
  const navigate = useNavigate();
  const [pin, setPin] = useState('');

  const handleKeyPress = (key: string) => {
    if (pin.length < 6) {
      setPin(prev => prev + key);
    }
  };

  const handleDelete = () => {
    setPin(prev => prev.slice(0, -1));
  };

  useEffect(() => {
    if (pin.length === 6) {
      // automatically navigate when 6 digits are entered
      setTimeout(() => navigate('/home'), 300);
    }
  }, [pin, navigate]);

  return (
    <div className="union-mpin" data-testid="UNION-MPIN">
      <div className="union-mpin-header">
        <h2>Enter Login PIN</h2>
        <p>Please enter your 6-digit MPIN</p>
      </div>
      
      <div className="union-mpin-dots">
        {[...Array(6)].map((_, i) => (
          <div key={i} className={`pin-dot ${i < pin.length ? 'filled' : ''}`} />
        ))}
      </div>

      <div className="union-mpin-pad-container">
        <PINPad onKeyPress={handleKeyPress} onDelete={handleDelete} />
      </div>
      
      <div className="union-mpin-footer">
        <button className="forgot-btn" onClick={() => {}}>Forgot Login PIN?</button>
      </div>
    </div>
  );
}
