import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { Button } from '../components/primitives/Button';
import { PINPad } from '../components/primitives/PINPad';

export const Review: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const txDetails = location.state || { payeeName: 'Unknown', accountNumber: 'XXXX', amount: 0, fromAccount: 'XXXX', remarks: '' };
  
  const [showPin, setShowPin] = useState(false);
  const [pin, setPin] = useState('');

  const handleConfirm = () => {
    setShowPin(true);
  };

  const handlePinChange = (newPin: string) => {
    setPin(newPin);
    if (newPin.length === 6) {
      setTimeout(() => {
        navigate('/transfer/receipt', { state: txDetails });
      }, 300);
    }
  };

  return (
    <div style={{ minHeight: '100vh', backgroundColor: 'var(--color-background)', position: 'relative' }}>
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
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Review Transfer</h2>
      </div>

      <div style={{ padding: 'var(--spacing-3)' }}>
        <div style={{ textAlign: 'center', margin: 'var(--spacing-3) 0 var(--spacing-4) 0' }}>
          <div style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>Amount to be transferred</div>
          <div style={{ fontSize: '2.5rem', fontWeight: 700, color: 'var(--color-primary)' }}>
            ₹{txDetails.amount.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
          </div>
        </div>

        <div style={{ 
          backgroundColor: 'var(--color-surface)',
          borderRadius: 'var(--radius-card)',
          padding: 'var(--spacing-3)',
          marginBottom: 'var(--spacing-4)',
          boxShadow: '0 2px 8px rgba(0,0,0,0.05)'
        }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-3)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>From Account</span>
              <span style={{ fontWeight: 500, fontSize: '0.875rem' }}>{txDetails.fromAccount}</span>
            </div>
            <div style={{ height: '1px', backgroundColor: 'var(--color-divider)' }} />
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>To Account</span>
              <span style={{ fontWeight: 500, fontSize: '0.875rem', textAlign: 'right' }}>
                <div>{txDetails.payeeName}</div>
                <div style={{ color: 'var(--color-text-secondary)', marginTop: '4px' }}>{txDetails.accountNumber}</div>
              </span>
            </div>
            {txDetails.remarks && (
              <>
                <div style={{ height: '1px', backgroundColor: 'var(--color-divider)' }} />
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>Remarks</span>
                  <span style={{ fontWeight: 500, fontSize: '0.875rem' }}>{txDetails.remarks}</span>
                </div>
              </>
            )}
          </div>
        </div>

        <Button variant="primary" fullWidth onClick={handleConfirm}>
          Confirm Transfer
        </Button>
      </div>

      {showPin && (
        <div style={{
          position: 'absolute',
          top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'var(--color-surface)',
          zIndex: 100,
          padding: 'var(--spacing-4)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <h3 style={{ marginBottom: 'var(--spacing-1)' }}>Enter MPIN</h3>
          <p style={{ color: 'var(--color-text-secondary)', marginBottom: 'var(--spacing-4)', textAlign: 'center' }}>
            Enter your 6-digit MPIN to confirm transfer of ₹{txDetails.amount}
          </p>
          
          <div style={{ display: 'flex', gap: 'var(--spacing-2)', marginBottom: 'var(--spacing-4)' }}>
            {Array.from({ length: 6 }).map((_, i) => (
              <div 
                key={i}
                style={{
                  width: '16px',
                  height: '16px',
                  borderRadius: '50%',
                  backgroundColor: i < pin.length ? 'var(--color-primary)' : 'var(--color-divider)',
                  transition: 'background-color 0.2s'
                }}
              />
            ))}
          </div>

          <div style={{ width: '100%', maxWidth: '320px' }}>
            <PINPad 
              onKeyPress={(key) => handlePinChange(pin.length < 6 ? pin + key : pin)}
              onDelete={() => handlePinChange(pin.slice(0, -1))}
            />
          </div>

          <Button variant="secondary" onClick={() => setShowPin(false)} style={{ marginTop: 'var(--spacing-4)' }}>
            Cancel
          </Button>
        </div>
      )}
    </div>
  );
};
