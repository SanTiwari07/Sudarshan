import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Search } from 'lucide-react';
import { InputField } from '../components/primitives/InputField';

export const Transfer: React.FC = () => {
  const navigate = useNavigate();

  const payees = [
    { id: 1, name: 'Rahul Sharma', account: 'XXXX-1234', bank: 'ICICI Bank' },
    { id: 2, name: 'Neha Gupta', account: 'XXXX-5678', bank: 'HDFC Bank' },
    { id: 3, name: 'Ramesh Landlord', account: 'XXXX-9012', bank: 'SBI' },
  ];

  return (
    <div style={{ backgroundColor: 'var(--color-background)', minHeight: '100vh' }}>
      <header style={{
        backgroundColor: 'var(--color-primary)',
        padding: 'var(--spacing-3) var(--spacing-2)',
        color: 'var(--color-surface)',
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--spacing-2)',
      }}>
        <ArrowLeft size={24} onClick={() => navigate(-1)} style={{ cursor: 'pointer' }} />
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Select Payee</h2>
      </header>

      <div style={{ padding: 'var(--spacing-2)' }}>
        <div style={{ marginBottom: 'var(--spacing-3)' }}>
          <InputField placeholder="Search by Name or Account Number" icon={<Search size={20} />} />
        </div>

        <div style={{ backgroundColor: 'var(--color-surface)', borderRadius: 'var(--radius-card)', overflow: 'hidden' }}>
          <div style={{ padding: 'var(--spacing-2)', borderBottom: '1px solid var(--color-divider)' }}>
            <h3 style={{ margin: 0, fontSize: '1rem', color: 'var(--color-text-secondary)' }}>Recent Payees</h3>
          </div>
          {payees.map((payee) => (
            <div key={payee.id} onClick={() => navigate('/transfer/amount')} style={{
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--spacing-2)',
              padding: 'var(--spacing-3)',
              borderBottom: '1px solid var(--color-divider)',
              cursor: 'pointer'
            }}>
              <div style={{
                width: '40px',
                height: '40px',
                borderRadius: '50%',
                backgroundColor: 'var(--color-secondary)',
                color: 'var(--color-surface)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 'bold'
              }}>
                {payee.name.charAt(0)}
              </div>
              <div>
                <p style={{ margin: '0 0 4px', fontWeight: 500, color: 'var(--color-text-primary)' }}>{payee.name}</p>
                <p style={{ margin: 0, fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>
                  {payee.bank} | {payee.account}
                </p>
              </div>
            </div>
          ))}
          <div style={{ padding: 'var(--spacing-3)', textAlign: 'center', color: 'var(--color-primary)', cursor: 'pointer', fontWeight: 500 }}>
            + Add New Payee
          </div>
        </div>
      </div>
    </div>
  );
};
