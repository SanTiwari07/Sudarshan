import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { mockUser } from '../data/mockData';

export const Cards: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div style={{ backgroundColor: 'var(--color-bg)', minHeight: '100%' }}>
      <Header title="My Cards" showBack onBack={() => navigate('/home')} />
      
      <div style={{ padding: 'var(--space-16)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {mockUser.cards.map((card, idx) => (
            <div 
              key={card.id}
              style={{
                background: idx === 0 
                  ? 'linear-gradient(135deg, #1A1A1A 0%, #333 100%)' 
                  : 'linear-gradient(135deg, var(--color-primary) 0%, var(--color-accent) 100%)',
                padding: '24px',
                borderRadius: '16px',
                color: 'white',
                boxShadow: '0 4px 12px rgba(0,0,0,0.15)'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '32px' }}>
                <span style={{ fontSize: '18px', fontWeight: 600 }}>{card.name}</span>
                <span style={{ fontSize: '14px', opacity: 0.9 }}>{card.type}</span>
              </div>
              
              <div style={{ fontSize: '20px', letterSpacing: '2px', marginBottom: '24px' }}>
                {card.number}
              </div>
              
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                <div>
                  <div style={{ fontSize: '12px', opacity: 0.8, marginBottom: '4px' }}>Card Holder</div>
                  <div style={{ fontSize: '14px', textTransform: 'uppercase' }}>{mockUser.name}</div>
                </div>
                {card.limit && (
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '12px', opacity: 0.8, marginBottom: '4px' }}>Limit</div>
                    <div style={{ fontSize: '14px', fontWeight: 600 }}>₹{card.limit.toLocaleString()}</div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
