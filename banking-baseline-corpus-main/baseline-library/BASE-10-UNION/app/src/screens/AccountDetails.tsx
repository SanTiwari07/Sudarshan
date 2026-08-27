
import { useNavigate, useParams } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';
import './AccountDetails.css';

export function AccountDetails() {
  const navigate = useNavigate();
  const { id } = useParams();

  return (
    <div className="union-account-details" data-testid="UNION-ACCOUNT_DETAILS">
      <Header title="Account Details" showBack />
      <div className="account-details-content">
        <div className="details-card">
          <div className="detail-row">
            <span>Account Type</span>
            <strong>{id === '2' ? 'Fixed Deposit' : 'Savings Account'}</strong>
          </div>
          <div className="detail-row">
            <span>Account Number</span>
            <strong>XXXX {id === '2' ? '5678' : '1234'}</strong>
          </div>
          <div className="detail-row">
            <span>IFSC Code</span>
            <strong>UBIN0531234</strong>
          </div>
          <div className="detail-row">
            <span>Branch</span>
            <strong>Mumbai Main</strong>
          </div>
          <div className="detail-row highlight">
            <span>Available Balance</span>
            <strong>₹ {id === '2' ? '1,00,000.00' : '45,230.00'}</strong>
          </div>
        </div>

        <div className="details-actions">
          <Button variant="primary" fullWidth onClick={() => navigate(`/accounts/${id}/transactions`)}>
            View Transactions
          </Button>
          <Button variant="secondary" fullWidth onClick={() => navigate('/transfer')}>
            Fund Transfer
          </Button>
        </div>
      </div>
    </div>
  );
}
