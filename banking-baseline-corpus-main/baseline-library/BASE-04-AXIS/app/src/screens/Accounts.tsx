import { useNavigate } from 'react-router-dom';
import { mockAccounts } from '../data/mockData';
import { Header } from '../components/layout/Header';
import './Accounts.css';

export default function Accounts() {
  const navigate = useNavigate();

  return (
    <div className="accounts-screen">
      <Header title="My Accounts" showBack={true} />
      
      <div className="accounts-content">
        <div className="accounts-list">
          {mockAccounts.map(account => (
            <div 
              key={account.id} 
              className="account-card"
              onClick={() => navigate(`/accounts/${account.id}`)}
            >
              <div className="acc-card-header">
                <div>
                  <h3 className="acc-type">{account.type} ACCOUNT</h3>
                  <p className="acc-name">{account.name}</p>
                </div>
                <div className="acc-icon">🏦</div>
              </div>
              <div className="acc-card-body">
                <p className="acc-num">{account.number}</p>
                <div className="acc-bal-row">
                  <span className="acc-bal-label">Available Balance</span>
                  <span className="acc-bal-amount">
                    ₹ {account.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
