import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, Search, QrCode, CreditCard, Smartphone, Send, IndianRupee } from 'lucide-react';
import { Button } from '../components/primitives/Button';

export const Home: React.FC = () => {
  const navigate = useNavigate();

  const MOCK_USER = "Priya";
  const MOCK_BALANCE = "1,45,230.50";

  const quickActions = [
    { icon: Send, label: 'Send Money', path: '/payments' },
    { icon: QrCode, label: 'Scan any QR', path: '/payments' },
    { icon: Smartphone, label: 'Recharge', path: '/payments' },
    { icon: CreditCard, label: 'Cards', path: '/accounts' },
  ];

  return (
    <div style={{ backgroundColor: 'var(--color-background)', minHeight: '100%', paddingBottom: '80px' }}>
      {/* Header */}
      <header style={{
        backgroundColor: 'var(--color-primary)',
        padding: 'var(--spacing-3) var(--spacing-2) var(--spacing-4)',
        color: 'var(--color-surface)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        borderBottomLeftRadius: '24px',
        borderBottomRightRadius: '24px',
      }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Welcome, {MOCK_USER}</h2>
          <p style={{ margin: '4px 0 0', opacity: 0.8, fontSize: '0.875rem' }}>Last login: Today 10:45 AM</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--spacing-2)' }}>
          <Search size={24} />
          <Bell size={24} />
        </div>
      </header>

      <div style={{ padding: '0 var(--spacing-2)', marginTop: '-24px' }}>
        {/* Account Summary Card */}
        <div style={{
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-card)',
          padding: 'var(--spacing-3)',
          boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)',
          marginBottom: 'var(--spacing-3)',
        }}>
          <p style={{ color: 'var(--color-text-secondary)', margin: '0 0 var(--spacing-1)' }}>Savings Account XX4321</p>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <IndianRupee size={24} />
            <h1 style={{ margin: 0, fontSize: '1.75rem', color: 'var(--color-text-primary)' }}>{MOCK_BALANCE}</h1>
          </div>
          <div style={{ marginTop: 'var(--spacing-2)', display: 'flex', gap: 'var(--spacing-2)' }}>
            <Button variant="outline" size="sm" onClick={() => navigate('/accounts/1')} style={{ flex: 1, borderColor: 'var(--color-primary)', color: 'var(--color-primary)' }}>
              Statement
            </Button>
            <Button variant="outline" size="sm" onClick={() => navigate('/accounts')} style={{ flex: 1, borderColor: 'var(--color-primary)', color: 'var(--color-primary)' }}>
              All Accounts
            </Button>
          </div>
        </div>

        {/* Quick Actions Grid */}
        <div style={{ marginBottom: 'var(--spacing-4)' }}>
          <h3 style={{ marginBottom: 'var(--spacing-2)', color: 'var(--color-text-primary)' }}>Quick Actions</h3>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: 'var(--spacing-1)',
          }}>
            {quickActions.map((action, idx) => {
              const Icon = action.icon;
              return (
                <div key={idx} onClick={() => navigate(action.path)} style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: '8px',
                  cursor: 'pointer'
                }}>
                  <div style={{
                    backgroundColor: 'var(--color-secondary)',
                    width: '48px',
                    height: '48px',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--color-surface)'
                  }}>
                    <Icon size={24} />
                  </div>
                  <span style={{ fontSize: '0.75rem', textAlign: 'center', color: 'var(--color-text-primary)' }}>
                    {action.label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Offers Strip */}
        <div style={{
          backgroundColor: '#FFF3E0',
          borderRadius: 'var(--radius-card)',
          padding: 'var(--spacing-2)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 'var(--spacing-4)',
          border: '1px solid var(--color-accent)'
        }}>
          <div>
            <h4 style={{ margin: '0 0 4px', color: 'var(--color-secondary)' }}>Pre-approved Loan</h4>
            <p style={{ margin: 0, fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>Get up to ₹5,00,000 instantly</p>
          </div>
          <Button variant="primary" size="sm" style={{ backgroundColor: 'var(--color-secondary)' }}>Apply</Button>
        </div>

        {/* Recent Activity */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--spacing-2)' }}>
            <h3 style={{ margin: 0, color: 'var(--color-text-primary)' }}>Recent Activity</h3>
            <span style={{ color: 'var(--color-primary)', fontSize: '0.875rem', cursor: 'pointer' }} onClick={() => navigate('/accounts/1/transactions')}>
              View All
            </span>
          </div>
          <div style={{ backgroundColor: 'var(--color-surface)', borderRadius: 'var(--radius-card)', overflow: 'hidden' }}>
            {[
              { id: 1, name: 'Amazon', date: '12 Aug 2026', amount: '-₹1,299.00', color: 'var(--color-error)' },
              { id: 2, name: 'Salary', date: '01 Aug 2026', amount: '+₹85,000.00', color: 'var(--color-success)' },
              { id: 3, name: 'Zomato', date: '30 Jul 2026', amount: '-₹450.00', color: 'var(--color-error)' },
            ].map((txn, idx) => (
              <div key={txn.id} style={{
                display: 'flex',
                justifyContent: 'space-between',
                padding: 'var(--spacing-2)',
                borderBottom: idx < 2 ? '1px solid var(--color-divider)' : 'none'
              }}>
                <div>
                  <h4 style={{ margin: '0 0 4px', color: 'var(--color-text-primary)' }}>{txn.name}</h4>
                  <span style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>{txn.date}</span>
                </div>
                <span style={{ fontWeight: 'bold', color: txn.color }}>{txn.amount}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
