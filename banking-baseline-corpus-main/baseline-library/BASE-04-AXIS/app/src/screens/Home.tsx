import { useNavigate } from 'react-router-dom';
import { mockUser, mockAccounts } from '../data/mockData';
import './Home.css';

export default function Home() {
  const navigate = useNavigate();
  const primaryAccount = mockAccounts[0];

  return (
    <div className="home-screen">
      <div className="home-header-bg"></div>
      
      <div className="home-content">
        <header className="home-header">
          <div className="user-greeting">
            <div className="avatar">{mockUser.name.charAt(0)}</div>
            <div>
              <p className="greeting-text">Hi, {mockUser.name}</p>
              <p className="last-login">Last login: {mockUser.lastLogin}</p>
            </div>
          </div>
          <button className="notif-btn">🔔</button>
        </header>

        <section className="account-summary-card">
          <div className="card-header">
            <h3>{primaryAccount.type} A/C</h3>
            <span className="acc-number">{primaryAccount.number}</span>
          </div>
          <div className="balance-info">
            <span className="currency">₹</span>
            <span className="amount">{primaryAccount.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</span>
          </div>
          <div className="card-actions">
            <button onClick={() => navigate('/accounts')}>View Statements</button>
          </div>
        </section>

        <section className="quick-actions">
          <div className="action-item" onClick={() => navigate('/transfer')}>
            <div className="action-icon">💸</div>
            <span>Transfer</span>
          </div>
          <div className="action-item" onClick={() => navigate('/transfer')}>
            <div className="action-icon">🧾</div>
            <span>Pay Bills</span>
          </div>
          <div className="action-item" onClick={() => navigate('/services')}>
            <div className="action-icon">📈</div>
            <span>Invest</span>
          </div>
          <div className="action-item" onClick={() => navigate('/transfer')}>
            <div className="action-icon">📷</div>
            <span>Scan QR</span>
          </div>
        </section>

        <section className="personalized-strip">
          <div className="promo-card">
            <h4>Pre-approved Personal Loan</h4>
            <p>Get up to ₹5,00,000 instantly in your account.</p>
            <button className="apply-btn">Apply Now</button>
          </div>
        </section>

        <section className="recent-activity">
          <h3>Recent Activity</h3>
          <div className="activity-list">
            <div className="activity-item">
              <div className="activity-icon">↑</div>
              <div className="activity-details">
                <p className="activity-desc">UPI/Zomato/123456</p>
                <p className="activity-date">10 Aug 2026</p>
              </div>
              <div className="activity-amount debit">- ₹450.00</div>
            </div>
            <div className="activity-item">
              <div className="activity-icon">↓</div>
              <div className="activity-details">
                <p className="activity-desc">NEFT/Salary/Corp</p>
                <p className="activity-date">09 Aug 2026</p>
              </div>
              <div className="activity-amount credit">+ ₹85,000.00</div>
            </div>
          </div>
          <button className="view-all-btn" onClick={() => navigate('/accounts/' + primaryAccount.id + '/history')}>
            View All Transactions
          </button>
        </section>
      </div>
    </div>
  );
}
