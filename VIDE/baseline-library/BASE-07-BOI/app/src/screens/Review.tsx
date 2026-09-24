import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { ChevronLeft } from 'lucide-react';
import { Button } from '../components/primitives/Button';
import { PINPad } from '../components/primitives/PINPad';
import './Review.css';

export const Review: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [showPin, setShowPin] = useState(false);
  
  const { payee, amount, account } = location.state || {};

  // If accessed directly without state, go back
  if (!payee || !amount) {
    navigate('/transfer');
    return null;
  }

  const handleConfirm = () => {
    setShowPin(true);
  };

  const handlePinComplete = (pin: string) => {
    console.log('Transaction PIN verified', pin);
    navigate('/transfer/receipt', { 
      state: { payee, amount, account, transactionId: `TXN${Math.floor(Math.random() * 1000000000)}` } 
    });
  };

  return (
    <div className="review-screen">
      <header className="screen-header">
        <button className="back-btn" onClick={() => navigate(-1)}>
          <ChevronLeft size={24} />
        </button>
        <h1>Review Transfer</h1>
        <div style={{ width: 24 }}></div>
      </header>

      {!showPin ? (
        <>
          <div className="review-content">
            <div className="review-card">
              <div className="review-amount">
                <p>Transfer Amount</p>
                <h2>₹{Number(amount).toLocaleString('en-IN')}</h2>
              </div>
              
              <div className="review-details">
                <div className="detail-row">
                  <span className="label">To</span>
                  <div className="value-group">
                    <span className="value">{payee.name}</span>
                    <span className="sub-value">{payee.bank} - {payee.account}</span>
                  </div>
                </div>
                
                <div className="detail-row">
                  <span className="label">From</span>
                  <div className="value-group">
                    <span className="value">{account.type}</span>
                    <span className="sub-value">{account.accountNumber}</span>
                  </div>
                </div>

                <div className="detail-row">
                  <span className="label">Date</span>
                  <span className="value">13 Aug 2026</span>
                </div>
              </div>
            </div>
          </div>

          <div className="bottom-action">
            <Button 
              variant="primary" 
              fullWidth 
              size="large"
              onClick={handleConfirm}
            >
              Confirm Transfer
            </Button>
          </div>
        </>
      ) : (
        <div className="pin-verification-section">
          <h2>Enter Transaction PIN</h2>
          <p>Verify your transfer of ₹{Number(amount).toLocaleString('en-IN')} to {payee.name}</p>
          <div className="pinpad-container">
            <PINPad length={6} onComplete={handlePinComplete} />
          </div>
          <button className="text-link" onClick={() => setShowPin(false)}>Cancel</button>
        </div>
      )}
    </div>
  );
};
