import { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { Button } from '../components/primitives/Button';
import './Amount.css';

export default function Amount() {
  const navigate = useNavigate();
  const location = useLocation();
  const payee = location.state?.payee || { name: 'Unknown', vpa: 'unknown@upi', initials: 'UN' };
  
  const [amount, setAmount] = useState('');
  const [remarks, setRemarks] = useState('');

  const handleContinue = () => {
    if (amount) {
      navigate('/transfer/review', { state: { payee, amount, remarks } });
    }
  };

  return (
    <div className="amount-screen page-container">
      <header className="page-header">
        <button className="back-button" onClick={() => navigate(-1)}>
          <ArrowLeft size={24} />
        </button>
        <h1>Enter Amount</h1>
      </header>

      <div className="page-content">
        <div className="payee-summary">
          <div className="payee-avatar-large">{payee.initials}</div>
          <h2>{payee.name}</h2>
          <p>{payee.vpa || payee.account}</p>
        </div>

        <div className="amount-input-container">
          <span className="currency-symbol">₹</span>
          <input 
            type="number" 
            className="amount-input" 
            placeholder="0" 
            value={amount} 
            onChange={e => setAmount(e.target.value)}
            autoFocus
          />
        </div>

        <div className="remarks-container">
          <input 
            type="text" 
            placeholder="Add a remark (optional)" 
            value={remarks} 
            onChange={e => setRemarks(e.target.value)}
          />
        </div>
      </div>

      <div className="action-footer">
        <Button variant="primary" fullWidth onClick={handleContinue} disabled={!amount}>
          Continue
        </Button>
      </div>
    </div>
  );
}
