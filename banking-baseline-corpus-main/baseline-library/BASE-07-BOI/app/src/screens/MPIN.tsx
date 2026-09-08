import React from 'react';
import { useNavigate } from 'react-router-dom';
import { PINPad } from '../components/primitives/PINPad';
import { mockData } from '../mock/data';
import { UserCircle2 } from 'lucide-react';
import './MPIN.css';

export const MPIN: React.FC = () => {
  const navigate = useNavigate();

  const handleComplete = (pin: string) => {
    // In a real app, we would validate the PIN here
    console.log('PIN entered:', pin);
    navigate('/home');
  };

  return (
    <div className="mpin-screen">
      <div className="mpin-header">
        <div className="user-avatar">
          <UserCircle2 size={56} className="avatar-icon" />
        </div>
        <h2>Welcome back,</h2>
        <h1>{mockData.user.name}</h1>
        <p>Enter 6-digit MPIN to login</p>
      </div>

      <div className="pinpad-container">
        <PINPad length={6} onComplete={handleComplete} />
      </div>

      <div className="mpin-footer">
        <button className="text-link">Forgot MPIN?</button>
        <button className="text-link">Login with User ID</button>
      </div>
    </div>
  );
};
