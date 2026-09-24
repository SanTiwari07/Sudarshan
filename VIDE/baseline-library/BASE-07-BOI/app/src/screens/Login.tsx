import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { InputField } from '../components/primitives/InputField';
import { Button } from '../components/primitives/Button';
import { Building2 } from 'lucide-react';
import './Login.css';

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const [mobile, setMobile] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (mobile.length > 0) {
      navigate('/mpin');
    }
  };

  return (
    <div className="login-screen">
      <div className="login-header">
        <div className="login-logo">
          <Building2 size={40} className="logo-icon-small" />
        </div>
        <h1>Welcome to BOI Mobile</h1>
        <p>Login to your account</p>
      </div>

      <form className="login-form" onSubmit={handleSubmit}>
        <InputField
          label="Mobile Number / User ID"
          value={mobile}
          onChange={(e) => setMobile(e.target.value)}
          placeholder="Enter registered mobile number"
          fullWidth
        />
        
        <div className="forgot-links">
          <button type="button" className="link-button">Forgot User ID?</button>
          <button type="button" className="link-button">Forgot MPIN?</button>
        </div>

        <Button type="submit" variant="primary" fullWidth size="large" className="login-btn">
          Proceed
        </Button>
      </form>

      <div className="register-section">
        <p>New to BOI Mobile?</p>
        <Button variant="outline" fullWidth>Register Now</Button>
      </div>
    </div>
  );
};
