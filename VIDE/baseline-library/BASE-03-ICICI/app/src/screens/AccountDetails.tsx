import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, IndianRupee, FileText, Send } from 'lucide-react';
import { Button } from '../components/primitives/Button';

export const AccountDetails: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams();

  const mockTxns = [
    { id: 1, name: 'Amazon', date: '12 Aug 2026', amount: '-₹1,299.00', color: 'var(--color-error)' },
    { id: 2, name: 'Salary', date: '01 Aug 2026', amount: '+₹85,000.00', color: 'var(--color-success)' },
    { id: 3, name: 'Zomato', date: '30 Jul 2026', amount: '-₹450.00', color: 'var(--color-error)' },
  ];

  return (
    <div style={{ backgroundColor: 'var(--color-background)', minHeight: '100vh', paddingBottom: '80px' }}>
      <header style={{
        backgroundColor: 'var(--color-primary)',
        padding: 'var(--spacing-3) var(--spacing-2) var(--spacing-4)',
        color: 'var(--color-surface)',
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--spacing-2)',
        borderBottomLeftRadius: '24px',
        borderBottomRightRadius: '24px',
      }}>
        <ArrowLeft size={24} onClick={() => navigate(-1)} style={{ cursor: 'pointer' }} />
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Savings Account</h2>
      </header>

      <div style={{ padding: '0 var(--spacing-2)', marginTop: '-24px' }}>
        <div style={{
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-card)',
          padding: 'var(--spacing-3)',
          boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)',
          marginBottom: 'var(--spacing-3)',
        }}>
          <p style={{ color: 'var(--color-text-secondary)', margin: '0 0 var(--spacing-1)' }}>Available Balance</p>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <IndianRupee size={28} />
            <h1 style={{ margin: 0, fontSize: '2rem', color: 'var(--color-text-primary)' }}>1,45,230.50</h1>
          </div>
          <p style={{ margin: '8px 0 0', fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>A/c No: XXXX-4321</p>
          <p style={{ margin: '4px 0 0', fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>IFSC: ICIC0001234</p>
          
          <div style={{ marginTop: 'var(--spacing-3)', display: 'flex', gap: 'var(--spacing-2)' }}>
            <Button variant="primary" size="sm" onClick={() => navigate('/transfer')} style={{ flex: 1, backgroundColor: 'var(--color-secondary)' }}>
              <Send size={16} style={{ marginRight: '8px' }} /> Transfer
            </Button>
            <Button variant="outline" size="sm" onClick={() => navigate(`/accounts/${id}/transactions`)} style={{ flex: 1, color: 'var(--color-primary)', borderColor: 'var(--color-primary)' }}>
              <FileText size={16} style={{ marginRight: '8px' }} /> Statement
            </Button>
          </div>
        </div>

        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--spacing-2)' }}>
            <h3 style={{ margin: 0, color: 'var(--color-text-primary)' }}>Recent Transactions</h3>
            <span style={{ color: 'var(--color-primary)', fontSize: '0.875rem', cursor: 'pointer' }} onClick={() => navigate(`/accounts/${id}/transactions`)}>
              View All
            </span>
          </div>
          <div style={{ backgroundColor: 'var(--color-surface)', borderRadius: 'var(--radius-card)', overflow: 'hidden' }}>
            {mockTxns.map((txn, idx) => (
              <div key={txn.id} style={{
                display: 'flex',
                justifyContent: 'space-between',
                padding: 'var(--spacing-2)',
                borderBottom: idx < mockTxns.length - 1 ? '1px solid var(--color-divider)' : 'none'
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
