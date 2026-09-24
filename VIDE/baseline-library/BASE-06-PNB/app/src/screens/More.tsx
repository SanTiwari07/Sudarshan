import React from 'react';
import { useNavigate } from 'react-router-dom';
import { User, LogOut, ChevronRight, Shield, CreditCard, HelpCircle, Settings } from 'lucide-react';
import { MOCK_USER } from '../data/mockData';

export const More: React.FC = () => {
  const navigate = useNavigate();

  const menuGroups = [
    {
      title: 'Profile & Settings',
      items: [
        { icon: User, label: 'My Profile', path: '/more' },
        { icon: Settings, label: 'App Settings', path: '/more' },
        { icon: Shield, label: 'Security & MPIN', path: '/more' },
      ]
    },
    {
      title: 'Services',
      items: [
        { icon: CreditCard, label: 'Manage Cards', path: '/more' },
        { icon: HelpCircle, label: 'Help & Support', path: '/more' },
      ]
    }
  ];

  return (
    <div style={{ paddingBottom: '80px', minHeight: '100vh', backgroundColor: 'var(--color-background)' }}>
      {/* Header */}
      <div style={{ 
        backgroundColor: 'var(--color-primary)', 
        color: 'white',
        padding: 'var(--spacing-3)',
        paddingTop: 'var(--spacing-4)',
        paddingBottom: '40px'
      }}>
        <h2 style={{ margin: 0, fontSize: '1.25rem', marginBottom: 'var(--spacing-3)' }}>More</h2>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-3)' }}>
          <div style={{ 
            width: '60px', height: '60px', 
            borderRadius: '50%', backgroundColor: 'rgba(255,255,255,0.2)',
            display: 'flex', justifyContent: 'center', alignItems: 'center'
          }}>
            <User size={32} />
          </div>
          <div>
            <h3 style={{ margin: '0 0 4px 0' }}>{MOCK_USER.name}</h3>
            <p style={{ margin: 0, fontSize: '0.875rem', opacity: 0.9 }}>Last Login: {MOCK_USER.lastLogin}</p>
          </div>
        </div>
      </div>

      <div style={{ padding: '0 var(--spacing-3)', marginTop: '-20px' }}>
        {menuGroups.map((group, gIdx) => (
          <div key={gIdx} style={{ marginBottom: 'var(--spacing-3)' }}>
            <h4 style={{ margin: '0 0 var(--spacing-2) 12px', fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>
              {group.title}
            </h4>
            <div style={{ 
              backgroundColor: 'var(--color-surface)',
              borderRadius: 'var(--radius-card)',
              overflow: 'hidden',
              boxShadow: '0 2px 8px rgba(0,0,0,0.05)'
            }}>
              {group.items.map((item, iIdx) => {
                const Icon = item.icon;
                return (
                  <div key={iIdx}>
                    <button
                      onClick={() => {}}
                      style={{
                        width: '100%',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '16px',
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        color: 'var(--color-text-primary)'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <Icon size={20} color="var(--color-primary)" />
                        <span style={{ fontSize: '1rem' }}>{item.label}</span>
                      </div>
                      <ChevronRight size={20} color="var(--color-text-secondary)" />
                    </button>
                    {iIdx < group.items.length - 1 && (
                      <div style={{ height: '1px', backgroundColor: 'var(--color-divider)', margin: '0 16px' }} />
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        ))}

        <button
          onClick={() => navigate('/login')}
          style={{
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
            padding: '16px',
            backgroundColor: 'var(--color-surface)',
            border: 'none',
            borderRadius: 'var(--radius-card)',
            color: 'var(--color-error)',
            fontSize: '1rem',
            fontWeight: 500,
            cursor: 'pointer',
            boxShadow: '0 2px 8px rgba(0,0,0,0.05)',
            marginBottom: 'var(--spacing-4)'
          }}
        >
          <LogOut size={20} /> Logout
        </button>
      </div>
    </div>
  );
};
