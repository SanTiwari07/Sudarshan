
import { useNavigate, useLocation } from 'react-router-dom';
import { Button } from '../components/primitives/Button';
import { CheckCircle, Share2, Download } from 'lucide-react';
import './Receipt.css';

export function Receipt() {
  const navigate = useNavigate();
  const location = useLocation();
  const { payee, amount } = location.state || { payee: { name: 'Unknown', bank: 'Unknown', acc: 'XXXX' }, amount: '0.00' };

  return (
    <div className="union-receipt" data-testid="UNION-RECEIPT">
      <div className="receipt-content">
        <div className="success-icon-wrap">
          <CheckCircle size={64} color="var(--color-success)" />
        </div>
        <h2 className="success-msg">Payment Successful!</h2>
        <p className="success-date">12 Aug 2026, 10:45 AM</p>

        <div className="receipt-card">
          <div className="receipt-amount">
            <span>Amount Paid</span>
            <h3>₹ {amount}</h3>
          </div>
          
          <div className="receipt-divider"></div>

          <div className="receipt-details">
            <div className="receipt-row">
              <span>Paid To</span>
              <strong>{payee.name}</strong>
            </div>
            <div className="receipt-row">
              <span>Account No.</span>
              <strong>{payee.acc}</strong>
            </div>
            <div className="receipt-row">
              <span>Paid From</span>
              <strong>Savings A/c XXXX 1234</strong>
            </div>
            <div className="receipt-row">
              <span>Ref ID</span>
              <strong>IMPS234987123984</strong>
            </div>
          </div>
        </div>

        <div className="receipt-tools">
          <button className="tool-btn">
            <Share2 size={20} />
            <span>Share</span>
          </button>
          <button className="tool-btn">
            <Download size={20} />
            <span>Download</span>
          </button>
        </div>

        <div className="receipt-actions">
          <Button variant="primary" fullWidth onClick={() => navigate('/home')}>
            Back to Home
          </Button>
        </div>
      </div>
    </div>
  );
}
