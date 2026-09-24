import { useNavigate, useLocation } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { Button } from '../components/primitives/Button';
import { mockAccounts } from '../data/mockData';
import './Review.css';

export default function Review() {
  const navigate = useNavigate();
  const location = useLocation();
  const { payee, amount, remarks } = location.state || { payee: null, amount: 0, remarks: '' };
  
  const fromAccount = mockAccounts[0]; // mock primary account

  if (!payee) return null; // Or redirect

  const handleConfirm = () => {
    // In a real app, this would show PIN pad. Here we just redirect to receipt.
    navigate('/transfer/receipt', { state: { payee, amount, remarks, fromAccount, success: true } });
  };

  return (
    <div className="review-screen page-container">
      <header className="page-header">
        <button className="back-button" onClick={() => navigate(-1)}>
          <ArrowLeft size={24} />
        </button>
        <h1>Confirm Payment</h1>
      </header>

      <div className="page-content">
        <div className="review-card">
          <div className="review-amount">
            <span className="currency">₹</span>
            <span>{parseFloat(amount).toLocaleString('en-IN', { minimumFractionDigits: 2 })}</span>
          </div>
          
          <div className="review-details">
            <div className="detail-row">
              <span className="detail-label">Paying To</span>
              <div className="detail-value right-align">
                <span className="bold">{payee.name}</span>
                <span className="sub-text">{payee.vpa || payee.account}</span>
              </div>
            </div>
            
            <div className="divider"></div>
            
            <div className="detail-row">
              <span className="detail-label">Paying From</span>
              <div className="detail-value right-align">
                <span className="bold">{fromAccount.type} A/C</span>
                <span className="sub-text">{fromAccount.number}</span>
              </div>
            </div>
            
            {remarks && (
              <>
                <div className="divider"></div>
                <div className="detail-row">
                  <span className="detail-label">Remarks</span>
                  <span className="detail-value right-align">{remarks}</span>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="action-footer">
        <Button variant="primary" fullWidth onClick={handleConfirm}>
          Confirm & Pay
        </Button>
      </div>
    </div>
  );
}
