
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import './Accounts.css';

export function Accounts() {
  const navigate = useNavigate();

  return (
    <div className="union-accounts" data-testid="UNION-ACCOUNTS">
      <Header title="My Accounts" showBack />
      <div className="accounts-content">
        <div className="accounts-list">
          <div className="account-card" onClick={() => navigate('/accounts/1')}>
            <div className="acct-header">
              <h4>Savings Account</h4>
              <span className="acct-num">XXXX 1234</span>
            </div>
            <div className="acct-balance">
              <span>Available Balance</span>
              <h3>₹ 45,230.00</h3>
            </div>
          </div>
          <div className="account-card" onClick={() => navigate('/accounts/2')}>
            <div className="acct-header">
              <h4>Fixed Deposit</h4>
              <span className="acct-num">XXXX 5678</span>
            </div>
            <div className="acct-balance">
              <span>Principal Amount</span>
              <h3>₹ 1,00,000.00</h3>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
