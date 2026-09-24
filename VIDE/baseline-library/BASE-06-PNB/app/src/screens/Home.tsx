import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, User, Send, CreditCard, FileText, Grid, Eye, EyeOff } from 'lucide-react';
import { MOCK_USER, MOCK_ACCOUNTS, MOCK_TRANSACTIONS } from '../data/mockData';

export const Home: React.FC = () => {
  const navigate = useNavigate();
  const [showBalance, setShowBalance] = useState(false);

  const mainAccount = MOCK_ACCOUNTS[0];
  const recentTxns = MOCK_TRANSACTIONS.slice(0, 3);

  const quickActions = [
    { icon: Send, label: 'Transfer', path: '/transfer' },
    { icon: CreditCard, label: 'Pay Bills', path: '/more' },
    { icon: FileText, label: 'Passbook', path: '/accounts/history' },
    { icon: Grid, label: 'Services', path: '/more' }
  ];

  return (
    <div style={{ paddingBottom: '80px', minHeight: '100vh', backgroundColor: 'var(--color-background)' }}>
      {/* Header */}
      <div style={{ 
        backgroundColor: 'var(--color-primary)', 
        color: 'white',
        padding: 'var(--spacing-3)',
        paddingTop: 'var(--spacing-4)',
        borderBottomLeftRadius: '24px',
        borderBottomRightRadius: '24px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--spacing-3)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-2)' }}>
            <div style={{ 
              width: '40px', height: '40px', 
              borderRadius: '50%', backgroundColor: 'rgba(255,255,255,0.2)',
              display: 'flex', justifyContent: 'center', alignItems: 'center'
            }}>
              <User size={20} />
            </div>
            <div>
              <p style={{ margin: 0, fontSize: '0.875rem', opacity: 0.9 }}>Welcome,</p>
              <h3 style={{ margin: 0 }}>{MOCK_USER.name}</h3>
            </div>
          </div>
          <button style={{ background: 'none', border: 'none', color: 'white', cursor: 'pointer' }}>
            <Bell size={24} />
          </button>
        </div>

        {/* Account Summary Card */}
        <div style={{ 
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-card)',
          padding: 'var(--spacing-3)',
          color: 'var(--color-text-primary)',
          boxShadow: '0 4px 12px rgba(0,0,0,0.1)'
        }} onClick={() => navigate('/accounts')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--spacing-2)' }}>
            <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>{mainAccount.type}</span>
            <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>{mainAccount.accountNumber}</span>
          </div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-2)' }}>
            <h2 style={{ margin: 0, fontSize: '2rem' }}>
              {showBalance ? `${mainAccount.currency} ${mainAccount.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}` : 'XXXXXX.XX'}
            </h2>
            <button 
              onClick={(e) => { e.stopPropagation(); setShowBalance(!showBalance); }}
              style={{ background: 'none', border: 'none', color: 'var(--color-primary)', cursor: 'pointer', display: 'flex' }}
            >
              {showBalance ? <EyeOff size={20} /> : <Eye size={20} />}
            </button>
          </div>
          <div style={{ marginTop: 'var(--spacing-2)', fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
            View Account Details &gt;
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div style={{ padding: 'var(--spacing-3)' }}>
        <h3 style={{ marginBottom: 'var(--spacing-2)', fontSize: '1.125rem' }}>Quick Actions</h3>
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(4, 1fr)', 
          gap: 'var(--spacing-2)' 
        }}>
          {quickActions.map((action, idx) => {
            const Icon = action.icon;
            return (
              <button
                key={idx}
                onClick={() => navigate(action.path)}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: 'var(--spacing-1)',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  padding: 0
                }}
              >
                <div style={{
                  width: '48px',
                  height: '48px',
                  borderRadius: '12px',
                  backgroundColor: 'var(--color-surface)',
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  color: 'var(--color-primary)',
                  boxShadow: '0 2px 8px rgba(0,0,0,0.05)'
                }}>
                  <Icon size={24} />
                </div>
                <span style={{ fontSize: '0.75rem', fontWeight: 500 }}>{action.label}</span>
              </button>
            )
          })}
        </div>
      </div>

      {/* Recent Activity */}
      <div style={{ padding: '0 var(--spacing-3)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--spacing-2)' }}>
          <h3 style={{ margin: 0, fontSize: '1.125rem' }}>Recent Transactions</h3>
          <button 
            onClick={() => navigate('/accounts/history')}
            style={{ background: 'none', border: 'none', color: 'var(--color-primary)', fontSize: '0.875rem', fontWeight: 500, cursor: 'pointer' }}
          >
            View All
          </button>
        </div>
        
        <div style={{ backgroundColor: 'var(--color-surface)', borderRadius: 'var(--radius-card)', padding: 'var(--spacing-2)' }}>
          {recentTxns.map((txn, idx) => (
            <div key={txn.id}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--spacing-2) 0' }}>
                <div>
                  <div style={{ fontWeight: 500, marginBottom: '4px' }}>{txn.description}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>{txn.date}</div>
                </div>
                <div style={{ 
                  fontWeight: 600, 
                  color: txn.amount < 0 ? 'var(--color-text-primary)' : 'var(--color-success)' 
                }}>
                  {txn.amount < 0 ? '-' : '+'}₹{Math.abs(txn.amount).toFixed(2)}
                </div>
              </div>
              {idx < recentTxns.length - 1 && <div style={{ height: '1px', backgroundColor: 'var(--color-divider)' }} />}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
