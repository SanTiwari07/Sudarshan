import { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';
import './Amount.css';

export function Amount() {
  const navigate = useNavigate();
  const location = useLocation();
  const [amount, setAmount] = useState('');
  
  const payee = location.state?.payee || { name: 'Unknown', bank: 'Unknown', acc: 'XXXX' };

  return (
    <div className="union-amount" data-testid="UNION-AMOUNT">
      <Header title="Enter Amount" showBack />
      
      <div className="amount-content">
        <div className="payee-summary">
          <span>Transferring to</span>
          <h3>{payee.name}</h3>
          <p>{payee.bank} • {payee.acc}</p>
        </div>

        <div className="amount-input-container">
          <span className="currency-symbol">₹</span>
          <input 
            type="number" 
            className="amount-input" 
            placeholder="0.00" 
            value={amount}
            onChange={e => setAmount(e.target.value)}
            autoFocus
          />
        </div>
        
        <div className="remarks-input">
          <input type="text" placeholder="Add Remarks (Optional)" />
        </div>

        <div className="from-account">
          <span>From</span>
          <div className="account-selector">
            <div>
              <strong>Savings Account</strong>
              <p>XXXX 1234 • Avail Bal: ₹ 45,230.00</p>
            </div>
          </div>
        </div>

        <div className="amount-actions">
          <Button 
            variant="primary" 
            fullWidth 
            disabled={!amount || Number(amount) <= 0}
            onClick={() => navigate('/transfer/review', { state: { payee, amount } })}
          >
            Continue
          </Button>
        </div>
      </div>
    </div>
  );
}
