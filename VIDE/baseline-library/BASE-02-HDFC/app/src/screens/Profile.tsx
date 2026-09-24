import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';
import { mockUser } from '../data/mockData';
import { User, Settings, Shield, Bell, LogOut, ChevronRight } from 'lucide-react';

export const Profile: React.FC = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    navigate('/login');
  };

  const menuItems = [
    { icon: User, label: 'Personal Details' },
    { icon: Settings, label: 'Account Settings' },
    { icon: Shield, label: 'Security' },
    { icon: Bell, label: 'Notifications' },
  ];

  return (
    <div style={{ backgroundColor: 'var(--color-bg)', minHeight: '100%', display: 'flex', flexDirection: 'column' }}>
      <Header title="Profile" showBack onBack={() => navigate('/home')} />
      
      <div style={{ padding: 'var(--space-16)', flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div style={{
          backgroundColor: 'var(--color-surface)',
          padding: '24px',
          borderRadius: 'var(--radius-card)',
          boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
          display: 'flex',
          alignItems: 'center',
          marginBottom: '24px'
        }}>
          <div style={{
            width: '64px',
            height: '64px',
            borderRadius: '32px',
            backgroundColor: 'var(--color-primary)',
            color: 'white',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '24px',
            fontWeight: 600,
            marginRight: '16px'
          }}>
            {mockUser.name.charAt(0)}
          </div>
          <div>
            <h2 style={{ margin: '0 0 4px 0', fontSize: '20px', color: 'var(--color-text-primary)' }}>{mockUser.name}</h2>
            <div style={{ color: 'var(--color-text-secondary)', fontSize: '14px' }}>Last login: {mockUser.lastLogin}</div>
          </div>
        </div>

        <div style={{
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-card)',
          boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
          overflow: 'hidden',
          marginBottom: '32px'
        }}>
          {menuItems.map((item, idx) => (
            <div 
              key={idx}
              style={{
                display: 'flex',
                alignItems: 'center',
                padding: '16px',
                borderBottom: idx < menuItems.length - 1 ? '1px solid var(--color-divider)' : 'none',
                cursor: 'pointer'
              }}
            >
              <item.icon size={20} style={{ color: 'var(--color-primary)', marginRight: '16px' }} />
              <span style={{ flex: 1, fontSize: '16px', color: 'var(--color-text-primary)' }}>{item.label}</span>
              <ChevronRight size={20} style={{ color: 'var(--color-text-secondary)' }} />
            </div>
          ))}
        </div>

        <div style={{ marginTop: 'auto' }}>
          <Button variant="secondary" fullWidth onClick={handleLogout} style={{ color: 'var(--color-error)', borderColor: 'var(--color-error)' }}>
            <LogOut size={20} style={{ marginRight: '8px' }} />
            Logout
          </Button>
        </div>
      </div>
    </div>
  );
};
