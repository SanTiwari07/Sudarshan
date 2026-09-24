import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';
import { mockUser } from '../data/mockData';

export const Profile: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)', height: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Header title="Profile" />
      <div className="page-content" style={{ padding: '16px', flex: 1 }}>
        <div style={{ backgroundColor: 'white', padding: '24px', borderRadius: '16px', textAlign: 'center', marginBottom: '24px' }}>
          <div style={{ width: '80px', height: '80px', borderRadius: '40px', backgroundColor: 'var(--color-primary)', color: 'white', margin: '0 auto 16px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '32px' }}>
            {mockUser.name.charAt(0)}
          </div>
          <h2>{mockUser.name}</h2>
          <p style={{ color: 'var(--color-text-secondary)' }}>Last login: {mockUser.lastLogin}</p>
        </div>
        
        <div style={{ backgroundColor: 'white', borderRadius: '16px', padding: '8px 16px' }}>
          <div style={{ padding: '16px 0', borderBottom: '1px solid var(--color-divider)' }}>Settings</div>
          <div style={{ padding: '16px 0' }}>Security</div>
        </div>

        <div style={{ marginTop: '32px' }}>
          <Button variant="secondary" fullWidth onClick={() => navigate('/login')}>Logout</Button>
        </div>
      </div>
    </div>
  );
};
