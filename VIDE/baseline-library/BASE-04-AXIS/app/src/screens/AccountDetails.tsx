import { useParams, useNavigate } from 'react-router-dom';
import { mockAccounts } from '../data/mockData';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';
import './AccountDetails.css';

export default function AccountDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const account = mockAccounts.find(a => a.id === id) || mockAccounts[0];

  return (
    <div className="acc-details-screen">
      <Header title="Account Details" showBack={true} />
      
      <div className="acc-details-content">
        <div className="details-card">
          <div className="details-header">
            <h2>{account.type} ACCOUNT</h2>
            <p className="details-num">{account.number}</p>
          </div>
          
          <div className="details-bal">
            <span className="details-bal-label">Available Balance</span>
            <span className="details-bal-amount">
              ₹ {account.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
            </span>
          </div>
          
          <div className="details-info">
            <div className="info-row">
              <span className="info-label">Account Holder Name</span>
              <span className="info-val">{account.name}</span>
            </div>
            <div className="info-row">
              <span className="info-label">IFSC Code</span>
              <span className="info-val">UTIB0001234</span>
            </div>
            <div className="info-row">
              <span className="info-label">Branch</span>
              <span className="info-val">MUMBAI MAIN</span>
            </div>
          </div>
        </div>

        <div className="details-actions">
          <Button variant="primary" fullWidth onClick={() => navigate(`/accounts/${id}/history`)}>
            View Statement
          </Button>
          <Button variant="secondary" fullWidth onClick={() => navigate('/transfer')}>
            Transfer Funds
          </Button>
        </div>
      </div>
    </div>
  );
}
