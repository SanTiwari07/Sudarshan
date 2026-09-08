import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { PINPad } from '../components/primitives/PINPad';
import './MPIN.css';

export default function MPIN() {
  const navigate = useNavigate();
  const [pin, setPin] = useState('');

  const handleKeyPress = (key: string) => {
    if (key === 'backspace') {
      setPin(prev => prev.slice(0, -1));
    } else if (pin.length < 6) {
      setPin(prev => prev + key);
    }
  };

  useEffect(() => {
    if (pin.length === 6) {
      const timer = setTimeout(() => {
        navigate('/home');
      }, 300);
      return () => clearTimeout(timer);
    }
  }, [pin, navigate]);

  return (
    <div className="mpin-screen">
      <div className="mpin-header">
        <h2>Enter MPIN</h2>
        <p>Please enter your 6-digit MPIN</p>
      </div>
      
      <div className="mpin-display">
        {Array.from({ length: 6 }).map((_, i) => (
          <div 
            key={i} 
            className={`mpin-dot ${i < pin.length ? 'filled' : ''}`}
          />
        ))}
      </div>

      <div className="mpin-pad-container">
        <PINPad onKeyPress={handleKeyPress} onDelete={() => handleKeyPress('backspace')} />
      </div>
      
      <button className="forgot-mpin-btn">Forgot MPIN?</button>
    </div>
  );
}
