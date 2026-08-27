import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const Login: React.FC = () => {
  const navigate = useNavigate();
  const [crn, setCrn] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (crn) {
      navigate('/mpin');
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-gray-50 p-6">
      <div className="mt-12 mb-8">
        <h1 className="text-2xl font-bold mb-2" style={{ color: 'var(--color-text-primary)' }}>
          Welcome back
        </h1>
        <p style={{ color: 'var(--color-text-secondary)' }}>
          Enter your CRN or Customer ID to login
        </p>
      </div>

      <form onSubmit={handleSubmit} className="flex-1 flex flex-col">
        <div className="mb-6">
          <label className="block text-sm font-medium mb-2" style={{ color: 'var(--color-text-primary)' }}>
            CRN / Customer ID
          </label>
          <input
            type="text"
            className="w-full p-4 border rounded-xl"
            placeholder="Enter CRN"
            value={crn}
            onChange={(e) => setCrn(e.target.value)}
            style={{ borderColor: 'var(--color-divider)' }}
          />
        </div>

        <div className="flex justify-end mb-4">
          <button type="button" className="text-sm font-medium" style={{ color: 'var(--color-secondary)' }}>
            Forgot CRN?
          </button>
        </div>

        <div className="mt-auto">
          <button
            type="submit"
            className="w-full py-4 rounded-xl font-bold text-white mb-4"
            style={{ backgroundColor: crn ? 'var(--color-primary)' : 'var(--color-text-secondary)', opacity: crn ? 1 : 0.5 }}
            disabled={!crn}
          >
            Continue
          </button>
        </div>
      </form>
    </div>
  );
};

export default Login;
