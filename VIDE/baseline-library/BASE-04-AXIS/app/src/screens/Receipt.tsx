import { useNavigate, useLocation } from 'react-router-dom';
import { CheckCircle, Home, Share2 } from 'lucide-react';
import { Button } from '../components/primitives/Button';
import './Receipt.css';

export default function Receipt() {
  const navigate = useNavigate();
  const location = useLocation();
  const { payee, amount, success } = location.state || { payee: null, amount: 0, success: false };

  const txnId = `AXIS${Math.floor(Math.random() * 1000000000)}`;
  const date = new Date().toLocaleString('en-IN', { 
    day: '2-digit', month: 'short', year: 'numeric', 
    hour: '2-digit', minute: '2-digit', hour12: true 
  });

  return (
    <div className="receipt-screen page-container">
      <div className="page-content center-content">
        <div className={`status-icon ${success ? 'success' : 'error'}`}>
          {success ? <CheckCircle size={80} /> : <div className="error-icon">!</div>}
        </div>
        
        <h2 className="status-text">{success ? 'Payment Successful' : 'Payment Failed'}</h2>
        
        <div className="receipt-amount">
          ₹{parseFloat(amount).toLocaleString('en-IN', { minimumFractionDigits: 2 })}
        </div>
        
        <div className="receipt-card">
          <div className="receipt-row">
            <span className="receipt-label">To</span>
            <span className="receipt-value bold">{payee?.name}</span>
          </div>
          <div className="receipt-row">
            <span className="receipt-label">Account/VPA</span>
            <span className="receipt-value">{payee?.vpa || payee?.account}</span>
          </div>
          <div className="receipt-divider"></div>
          <div className="receipt-row">
            <span className="receipt-label">Date & Time</span>
            <span className="receipt-value">{date}</span>
          </div>
          <div className="receipt-row">
            <span className="receipt-label">Transaction ID</span>
            <span className="receipt-value mono">{txnId}</span>
          </div>
        </div>
      </div>

      <div className="receipt-actions">
        <Button variant="secondary" onClick={() => {}} fullWidth>
          <Share2 size={18} className="btn-icon" /> Share Receipt
        </Button>
        <Button variant="primary" onClick={() => navigate('/home')} fullWidth>
          <Home size={18} className="btn-icon" /> Back to Home
        </Button>
      </div>
    </div>
  );
}
