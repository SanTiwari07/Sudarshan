import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';
import { InputField } from '../components/primitives/InputField';
import './Login.css';

export function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    if (username || password) {
      navigate('/mpin');
    }
  };

  return (
    <div className="union-login" data-testid="UNION-LOGIN">
      <div className="union-login-header">
        <h1>Welcome to Vyom</h1>
        <p>Login to continue</p>
      </div>
      <form onSubmit={handleLogin} className="union-login-form">
        <InputField
          label="Customer ID / User ID"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Enter ID"
        />
        <InputField
          label="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Enter Password"
        />
        <Button type="submit" variant="primary" fullWidth className="union-login-submit">
          Login
        </Button>
      </form>
      <div className="union-login-actions">
        <Button variant="secondary" onClick={() => {}} fullWidth>
          Forgot Password?
        </Button>
      </div>
    </div>
  );
}
