import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';

export const Transfer: React.FC = () => {
  const navigate = useNavigate();

  const payees = [
    { id: '1', name: 'Amit Kumar', bank: 'HDFC Bank', number: 'XXXX1122' },
    { id: '2', name: 'Priya Singh', bank: 'ICICI Bank', number: 'XXXX3344' },
  ];

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)' }}>
      <Header title="Send Money" showBack />
      <div className="page-content" style={{ padding: '16px' }}>
        <h3 style={{ marginBottom: '16px' }}>Select Payee</h3>
        {payees.map(p => (
          <div 
            key={p.id}
            onClick={() => navigate('/transfer/amount')}
            style={{ 
              backgroundColor: 'white', 
              padding: '16px', 
              borderRadius: '12px',
              marginBottom: '12px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}
          >
            <div>
              <p style={{ fontWeight: 'bold' }}>{p.name}</p>
              <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>{p.bank} - {p.number}</p>
            </div>
          </div>
        ))}
        <div style={{ marginTop: '24px' }}>
          <Button fullWidth variant="secondary" onClick={() => {}}>+ Add New Payee</Button>
        </div>
      </div>
    </div>
  );
};
