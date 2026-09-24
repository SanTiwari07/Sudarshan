import React from 'react';
import { Header } from '../components/layout/Header';

export const Services: React.FC = () => {
  
  const services = ['Cards', 'Deposits', 'Cheque', 'Requests', 'Support'];

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)' }}>
      <Header title="Services" />
      <div className="page-content" style={{ padding: '16px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
          {services.map(s => (
            <div key={s} style={{ backgroundColor: 'white', padding: '24px', borderRadius: '12px', textAlign: 'center', fontWeight: 'bold' }}>
              {s}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
