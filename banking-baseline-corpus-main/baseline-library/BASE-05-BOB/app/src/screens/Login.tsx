import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/Button';
import { InputField } from '../components/InputField';

export const Login: React.FC = () => {
  const navigate = useNavigate();

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    navigate('/mpin');
  };

  return (
    <div className="flex flex-col h-full bg-white p-6">
      <div className="flex-1 flex flex-col justify-center max-w-sm mx-auto w-full">
        <div className="text-center mb-10">
          <h2 className="text-2xl font-bold text-[var(--color-primary)] mb-2">Welcome to bob World</h2>
          <p className="text-[var(--color-text-secondary)]">Please enter your credentials to login</p>
        </div>

        <form onSubmit={handleLogin} className="space-y-6">
          <InputField 
            label="Mobile Number / Customer ID" 
            placeholder="Enter User ID" 
            type="text" 
            required 
          />
          <InputField 
            label="Login Password" 
            placeholder="Enter Password" 
            type="password" 
            required 
          />
          
          <div className="flex justify-end">
            <button type="button" className="text-sm font-medium text-[var(--color-primary)]">
              Forgot Login PIN?
            </button>
          </div>

          <Button type="submit" variant="primary" fullWidth>
            LOGIN
          </Button>
        </form>

        <div className="mt-8 text-center">
          <p className="text-sm text-[var(--color-text-secondary)]">
            Don't have an account?{' '}
            <button type="button" className="font-bold text-[var(--color-primary)]">
              Open a Digital Account
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};
