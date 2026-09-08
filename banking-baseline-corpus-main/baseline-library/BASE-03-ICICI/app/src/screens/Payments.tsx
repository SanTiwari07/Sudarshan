import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Send, Smartphone, Zap, FileText, Building, User } from 'lucide-react';

export const Payments: React.FC = () => {
  const navigate = useNavigate();

  const paymentGroups = [
    {
      title: 'Send Money',
      items: [
        { icon: Send, label: 'To Account / Payee', path: '/transfer' },
        { icon: Smartphone, label: 'To Contact / UPI', path: '/transfer' },
        { icon: User, label: 'To Self', path: '/transfer' },
      ]
    },
    {
      title: 'Recharge & Pay Bills',
      items: [
        { icon: Smartphone, label: 'Mobile Recharge', path: '/transfer' },
        { icon: Zap, label: 'Electricity', path: '/transfer' },
        { icon: FileText, label: 'Postpaid', path: '/transfer' },
        { icon: Building, label: 'Rent', path: '/transfer' },
      ]
    }
  ];

  return (
    <div style={{ backgroundColor: 'var(--color-background)', minHeight: '100vh', paddingBottom: '80px' }}>
      <header style={{
        backgroundColor: 'var(--color-primary)',
        padding: 'var(--spacing-3) var(--spacing-2)',
        color: 'var(--color-surface)',
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--spacing-2)',
      }}>
        <ArrowLeft size={24} onClick={() => navigate(-1)} style={{ cursor: 'pointer' }} />
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Payments</h2>
      </header>

      <div style={{ padding: 'var(--spacing-2)' }}>
        {paymentGroups.map((group, idx) => (
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
                  <div key={itemIdx} onClick={() => navigate(item.path)} style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 'var(--spacing-2)',
                    padding: 'var(--spacing-3)',
                    borderBottom: itemIdx < group.items.length - 1 ? '1px solid var(--color-divider)' : 'none',
                    cursor: 'pointer'
                  }}>
                    <div style={{
                      backgroundColor: '#FEF3EB',
                      padding: '8px',
                      borderRadius: '8px',
                      color: 'var(--color-secondary)'
                    }}>
                      <Icon size={20} />
                    </div>
                    <span style={{ color: 'var(--color-text-primary)', fontWeight: 500 }}>
                      {item.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
