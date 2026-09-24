import React from 'react';
import { useNavigate } from 'react-router-dom';
import { MOCK_ACCOUNTS } from '../data/mockData';
import { ArrowLeft, FileText, Send } from 'lucide-react';
import { Button } from '../components/primitives/Button';

export const AccountDetails: React.FC = () => {
  const navigate = useNavigate();
  const account = MOCK_ACCOUNTS[0];

  return (
    <div style={{ paddingBottom: '80px', minHeight: '100vh', backgroundColor: 'var(--color-background)' }}>
      {/* Header */}
      <div style={{ 
        backgroundColor: 'var(--color-primary)', 
        color: 'white',
        padding: 'var(--spacing-3)',
        paddingTop: 'var(--spacing-4)',
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--spacing-2)'
      }}>
        <button onClick={() => navigate(-1)} style={{ background: 'none', border: 'none', color: 'white', cursor: 'pointer', padding: 0 }}>
          <ArrowLeft size={24} />
        </button>
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Account Details</h2>
      </div>

      <div style={{ padding: 'var(--spacing-3)' }}>
        <div style={{ 
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-card)',
          padding: 'var(--spacing-3)',
          marginBottom: 'var(--spacing-3)',
          boxShadow: '0 2px 8px rgba(0,0,0,0.05)',
          textAlign: 'center'
        }}>
          <h3 style={{ margin: '0 0 8px 0', fontSize: '1rem', color: 'var(--color-text-secondary)' }}>{account.type}</h3>
          <p style={{ margin: '0 0 16px 0', fontSize: '1.125rem', fontWeight: 500 }}>{account.accountNumber}</p>
          
          <div style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginBottom: '8px' }}>Available Balance</div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--color-primary)' }}>
            {account.currency} {account.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--spacing-2)', marginBottom: 'var(--spacing-3)' }}>
          <Button variant="primary" onClick={() => navigate('/transfer')} style={{ display: 'flex', justifyContent: 'center', gap: '8px' }}>
            <Send size={18} /> Transfer
          </Button>
          <Button variant="secondary" onClick={() => navigate('/accounts/history')} style={{ display: 'flex', justifyContent: 'center', gap: '8px' }}>
            <FileText size={18} /> Statement
          </Button>
        </div>

        <div style={{ 
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-card)',
          padding: 'var(--spacing-3)',
          boxShadow: '0 2px 8px rgba(0,0,0,0.05)',
        }}>
          <h4 style={{ margin: '0 0 var(--spacing-3) 0', fontSize: '1rem' }}>Account Information</h4>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-2)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>Account Name</span>
              <span style={{ fontWeight: 500, fontSize: '0.875rem' }}>Sudarshan Reddy</span>
            </div>
            <div style={{ height: '1px', backgroundColor: 'var(--color-divider)' }} />
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>IFSC Code</span>
              <span style={{ fontWeight: 500, fontSize: '0.875rem' }}>PUNB0123456</span>
            </div>
            <div style={{ height: '1px', backgroundColor: 'var(--color-divider)' }} />
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>Branch</span>
              <span style={{ fontWeight: 500, fontSize: '0.875rem' }}>Main Branch, City</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
