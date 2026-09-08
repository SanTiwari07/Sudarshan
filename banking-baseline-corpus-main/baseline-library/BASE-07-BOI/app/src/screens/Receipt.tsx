import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { CheckCircle2, Share2, Download } from 'lucide-react';
import { Button } from '../components/primitives/Button';
import './Receipt.css';

export const Receipt: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { payee, amount, transactionId } = location.state || {
    payee: { name: 'Unknown' },
    amount: '0',
    transactionId: 'UNKNOWN'
  };

  return (
    <div className="receipt-screen">
      <div className="receipt-content">
        <div className="success-icon-container">
          <CheckCircle2 size={64} className="success-icon" />
        </div>
        
        <h1>Transfer Successful</h1>
        <p className="success-message">Your payment has been processed successfully.</p>

        <div className="receipt-card">
          <div className="receipt-amount">
            <h2>₹{Number(amount).toLocaleString('en-IN')}</h2>
            <p>Paid to {payee.name}</p>
          </div>
          
          <div className="receipt-details">
            <div className="receipt-row">
              <span className="label">Transaction ID</span>
              <span className="value">{transactionId}</span>
            </div>
            <div className="receipt-row">
              <span className="label">Date & Time</span>
              <span className="value">13 Aug 2026, 01:30 PM</span>
            </div>
          </div>
        </div>

        <div className="receipt-actions">
          <button className="action-btn-outline">
            <Share2 size={20} />
            Share
          </button>
          <button className="action-btn-outline">
            <Download size={20} />
            Download
          </button>
        </div>
      </div>

      <div className="bottom-action">
        <Button 
          variant="primary" 
          fullWidth 
          size="large"
          onClick={() => navigate('/home')}
        >
          Back to Home
        </Button>
      </div>
    </div>
  );
};
