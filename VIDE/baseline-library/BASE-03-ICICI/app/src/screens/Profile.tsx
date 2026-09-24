import React from 'react';
import { useNavigate } from 'react-router-dom';
import { User, Settings, HelpCircle, FileText, LogOut, ChevronRight } from 'lucide-react';

export const Profile: React.FC = () => {
  const navigate = useNavigate();

  const menuGroups = [
    {
      title: 'Account Settings',
      items: [
        { icon: User, label: 'Personal Information' },
        { icon: FileText, label: 'KYC Details' },
        { icon: Settings, label: 'App Settings' },
      ]
    },
    {
      title: 'Support',
      items: [
        { icon: HelpCircle, label: 'Help & Support' },
        { icon: FileText, label: 'Terms & Conditions' },
      ]
    }
  ];

  return (
    <div style={{ backgroundColor: 'var(--color-background)', minHeight: '100vh', paddingBottom: '80px' }}>
      <header style={{
        backgroundColor: 'var(--color-primary)',
        padding: 'var(--spacing-4) var(--spacing-2) var(--spacing-4)',
        color: 'var(--color-surface)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        borderBottomLeftRadius: '24px',
        borderBottomRightRadius: '24px',
      }}>
        <div style={{
          width: '80px',
          height: '80px',
          borderRadius: '50%',
          backgroundColor: 'var(--color-secondary)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '2rem',
          fontWeight: 'bold',
          marginBottom: 'var(--spacing-2)'
        }}>
          P
        </div>
        <h2 style={{ margin: '0 0 4px', fontSize: '1.5rem' }}>Priya</h2>
        <p style={{ margin: 0, opacity: 0.8 }}>+91 98765 43210</p>
      </header>

      <div style={{ padding: 'var(--spacing-2)', marginTop: 'var(--spacing-2)' }}>
        {menuGroups.map((group, idx) => (
          <div key={idx} style={{ marginBottom: 'var(--spacing-4)' }}>
            <h3 style={{ color: 'var(--color-text-secondary)', marginBottom: 'var(--spacing-2)', fontSize: '1rem' }}>
              {group.title}
            </h3>
            <div style={{
              backgroundColor: 'var(--color-surface)',
              borderRadius: 'var(--radius-card)',
              overflow: 'hidden',
              boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
            }}>
              {group.items.map((item, itemIdx) => {
                const Icon = item.icon;
                return (
                  <div key={itemIdx} style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: 'var(--spacing-3)',
                    borderBottom: itemIdx < group.items.length - 1 ? '1px solid var(--color-divider)' : 'none',
                    cursor: 'pointer'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-2)' }}>
                      <Icon size={20} color="var(--color-primary)" />
                      <span style={{ color: 'var(--color-text-primary)' }}>{item.label}</span>
                    </div>
                    <ChevronRight size={20} color="var(--color-text-secondary)" />
                  </div>
                );
              })}
            </div>
          </div>
        ))}

        <div style={{
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-card)',
          overflow: 'hidden',
          boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
          marginTop: 'var(--spacing-4)'
        }}>
          <div onClick={() => navigate('/login')} style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--spacing-2)',
            padding: 'var(--spacing-3)',
            cursor: 'pointer',
            color: 'var(--color-error)'
          }}>
            <LogOut size={20} />
            <span style={{ fontWeight: 500 }}>Logout</span>
          </div>
        </div>
      </div>
    </div>
  );
};
