import { useParams } from 'react-router-dom';
import { mockAccounts, mockTransactions } from '../data/mockData';
import { Header } from '../components/layout/Header';
import './TxnHistory.css';

export default function TxnHistory() {
  const { id } = useParams();
  const accountId = id || '1';
  const account = mockAccounts.find(a => a.id === accountId) || mockAccounts[0];
  const transactions = mockTransactions[accountId] || [];

  return (
    <div className="txn-history-screen">
      <Header title="Mini Statement" showBack={true} />
      
      <div className="txn-history-content">
        <div className="txn-acc-header">
          <div>
            <p className="txn-acc-type">{account.type} ACCOUNT</p>
            <p className="txn-acc-num">{account.number}</p>
          </div>
          <div className="txn-acc-bal">
            <span className="txn-bal-label">Balance</span>
            <span className="txn-bal-val">₹ {account.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</span>
          </div>
        </div>

        <div className="txn-filters">
          <button className="filter-btn active">All</button>
          <button className="filter-btn">Credits</button>
          <button className="filter-btn">Debits</button>
        </div>

        <div className="txn-list">
          {transactions.map(txn => (
            <div key={txn.id} className="txn-item">
              <div className="txn-left">
                <div className={`txn-icon ${txn.type.toLowerCase()}`}>
                  {txn.type === 'CREDIT' ? '↓' : '↑'}
                </div>
                <div className="txn-details">
                  <p className="txn-desc">{txn.description}</p>
                  <p className="txn-date">{txn.date}</p>
                </div>
              </div>
              <div className={`txn-amount ${txn.type.toLowerCase()}`}>
                {txn.amount > 0 ? '+' : ''} {txn.amount.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
