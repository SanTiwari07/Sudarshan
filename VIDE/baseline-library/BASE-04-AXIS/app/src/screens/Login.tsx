import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';
import { InputField } from '../components/primitives/InputField';
import './Login.css';

export default function Login() {
  const navigate = useNavigate();

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    navigate('/mpin');
  };

  return (
    <div className="login-screen">
      <div className="login-header">
        <h1 className="login-title">Welcome to open</h1>
        <p className="login-subtitle">by Axis Bank</p>
      </div>

      <form className="login-form" onSubmit={handleLogin}>
        <InputField 
          label="Login ID / Customer ID" 
          placeholder="Enter your ID"
          type="text"
        />
        
        <div className="login-actions">
          <Button variant="primary" fullWidth type="submit">
            Proceed
          </Button>
        </div>
      </form>

      <div className="login-links">
        <button className="link-button" onClick={() => {}}>Forgot Login ID?</button>
        <button className="link-button" onClick={() => {}}>Register</button>
      </div>
    </div>
  );
}
