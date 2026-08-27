import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { mockUser } from '../data/mockData';
import { Wallet, Send, Menu, User } from 'lucide-react';

export const Home: React.FC = () => {
  const navigate = useNavigate();
  const mainAccount = mockUser.accounts[0];

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)' }}>
      <Header title="YONO SBI" />
      <div className="page-content" style={{ padding: '16px' }}>
        <h2>Good morning, {mockUser.name}</h2>
        
        {/* Account Summary Card */}
        <div 
          onClick={() => navigate(`/accounts/${mainAccount.id}`)}
          style={{ 
            backgroundColor: 'var(--color-primary)', 
            color: 'white', 
            padding: '20px', 
            borderRadius: '16px',
            marginTop: '16px',
            cursor: 'pointer'
          }}
        >
          <p>Available Balance</p>
          <h3 style={{ fontSize: '24px', margin: '8px 0' }}>{mainAccount.currency} {mainAccount.balance.toFixed(2)}</h3>
          <p>{mainAccount.number}</p>
        </div>

        {/* Quick Actions */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '24px' }}>
          <div onClick={() => navigate('/transfer')} style={{ backgroundColor: 'white', padding: '16px', borderRadius: '12px', textAlign: 'center', cursor: 'pointer' }}>
            <Send color="var(--color-primary)" />
            <p style={{ marginTop: '8px' }}>Transfer</p>
          </div>
          <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '12px', textAlign: 'center', cursor: 'pointer' }}>
            <Wallet color="var(--color-primary)" />
            <p style={{ marginTop: '8px' }}>Pay</p>
          </div>
          <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '12px', textAlign: 'center', cursor: 'pointer' }}>
            <Menu color="var(--color-primary)" />
            <p style={{ marginTop: '8px' }}>Scan & Pay</p>
          </div>
          <div onClick={() => navigate('/services')} style={{ backgroundColor: 'white', padding: '16px', borderRadius: '12px', textAlign: 'center', cursor: 'pointer' }}>
            <User color="var(--color-primary)" />
            <p style={{ marginTop: '8px' }}>Services</p>
          </div>
        </div>

        {/* Recent Activity */}
        <div style={{ marginTop: '24px', backgroundColor: 'white', padding: '16px', borderRadius: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3>Recent Activity</h3>
            <span style={{ color: 'var(--color-primary)', cursor: 'pointer' }} onClick={() => navigate(`/accounts/${mainAccount.id}/transactions`)}>View all</span>
          </div>
          <div style={{ marginTop: '16px' }}>
            {mockUser.transactions.map(txn => (
              <div key={txn.id} style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid var(--color-divider)' }}>
                <div>
                  <p style={{ fontWeight: 500 }}>{txn.description}</p>
                  <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>{txn.date}</p>
                </div>
                <div style={{ color: txn.amount > 0 ? 'var(--color-success)' : 'var(--color-text-primary)' }}>
                  {txn.amount > 0 ? '+' : ''}{txn.amount.toFixed(2)}
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
};
