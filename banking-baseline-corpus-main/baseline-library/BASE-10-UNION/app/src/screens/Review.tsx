
import { useNavigate, useLocation } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';
import './Review.css';

export function Review() {
  const navigate = useNavigate();
  const location = useLocation();
  const { payee, amount } = location.state || { payee: { name: 'Unknown', bank: 'Unknown', acc: 'XXXX' }, amount: '0.00' };

  return (
    <div className="union-review" data-testid="UNION-REVIEW">
      <Header title="Review Transfer" showBack />
      
      <div className="review-content">
        <div className="review-amount">
          <span>Amount to be transferred</span>
          <h2>₹ {amount}</h2>
        </div>

        <div className="review-details">
          <div className="review-row">
            <span>To</span>
            <strong>{payee.name}</strong>
          </div>
          <div className="review-row">
            <span>Bank Name</span>
            <strong>{payee.bank}</strong>
          </div>
          <div className="review-row">
            <span>Account No.</span>
            <strong>{payee.acc}</strong>
          </div>
          <div className="review-row">
            <span>From Account</span>
            <strong>Savings A/c XXXX 1234</strong>
          </div>
          <div className="review-row">
            <span>Transfer Type</span>
            <strong>IMPS (Instant)</strong>
          </div>
          <div className="review-row">
            <span>Remarks</span>
            <strong>Transfer</strong>
          </div>
        </div>

        <div className="review-actions">
          <Button variant="primary" fullWidth onClick={() => navigate('/transfer/receipt', { state: { payee, amount } })}>
            Confirm Transfer
          </Button>
        </div>
      </div>
    </div>
  );
}
