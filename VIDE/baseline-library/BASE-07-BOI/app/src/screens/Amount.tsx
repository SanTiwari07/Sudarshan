import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { ChevronLeft, IndianRupee } from 'lucide-react';
import { Button } from '../components/primitives/Button';
import { mockData } from '../mock/data';
import './Amount.css';

export const Amount: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [amount, setAmount] = useState('');
  
  // Get payee details from mock data if ID was passed
  const payeeId = location.state?.payeeId;
  const payee = mockData.payees.find(p => p.id === payeeId) || mockData.payees[0];
  const account = mockData.accounts[0];

  const handleContinue = () => {
    if (amount) {
      navigate('/transfer/review', { 
        state: { payee, amount, account } 
      });
    }
  };

  return (
    <div className="amount-screen">
      <header className="screen-header">
        <button className="back-btn" onClick={() => navigate(-1)}>
          <ChevronLeft size={24} />
        </button>
        <h1>Enter Amount</h1>
        <div style={{ width: 24 }}></div>
      </header>

      <div className="amount-content">
        <div className="payee-summary">
          <p>Paying to</p>
          <h3>{payee.name}</h3>
          <span>{payee.bank} - {payee.account}</span>
        </div>

        <div className="amount-input-section">
          <div className="currency-symbol">
            <IndianRupee size={32} />
          </div>
          <input
            type="number"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="0"
            className="amount-input"
            autoFocus
          />
        </div>

        <div className="account-selection">
          <p>From Account</p>
          <div className="account-card-small">
            <div>
              <h4>{account.accountNumber}</h4>
              <p>Bal: ₹{account.balance.toLocaleString('en-IN')}</p>
            </div>
          </div>
        </div>

        <div className="remarks-input">
          <input type="text" placeholder="Add remarks (optional)" />
        </div>
      </div>

      <div className="bottom-action">
        <Button 
          variant="primary" 
          fullWidth 
          size="large"
          disabled={!amount || Number(amount) <= 0}
          onClick={handleContinue}
        >
          Continue
        </Button>
      </div>
    </div>
  );
};
