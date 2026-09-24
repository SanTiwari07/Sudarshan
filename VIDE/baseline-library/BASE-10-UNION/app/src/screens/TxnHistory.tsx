
import { Header } from '../components/layout/Header';
import { Search, Filter } from 'lucide-react';
import './TxnHistory.css';

export function TxnHistory() {
  const transactions = [
    { id: '1', date: '11 Aug 2026', desc: 'Amazon', amount: '1,200.00', type: 'debit' },
    { id: '2', date: '01 Aug 2026', desc: 'Salary Credit', amount: '85,000.00', type: 'credit' },
    { id: '3', date: '28 Jul 2026', desc: 'Electricity Bill', amount: '1,500.00', type: 'debit' },
    { id: '4', date: '25 Jul 2026', desc: 'Grocery Store', amount: '3,450.00', type: 'debit' },
    { id: '5', date: '20 Jul 2026', desc: 'Fund Transfer - Rohan', amount: '5,000.00', type: 'debit' },
    { id: '6', date: '15 Jul 2026', desc: 'UPI - Swiggy', amount: '450.00', type: 'debit' },
  ];

  return (
    <div className="union-txn-history" data-testid="UNION-TXN_HISTORY">
      <Header title="Transactions" showBack />
      
      <div className="txn-tools">
        <div className="search-bar">
          <Search size={20} color="var(--color-text-secondary)" />
          <input type="text" placeholder="Search transactions..." />
        </div>
        <button className="filter-btn">
          <Filter size={20} />
        </button>
      </div>

      <div className="txn-list">
        {transactions.map(txn => (
          <div key={txn.id} className="txn-item">
            <div className="txn-info">
              <span className="txn-desc">{txn.desc}</span>
              <span className="txn-date">{txn.date}</span>
            </div>
            <div className="txn-amount-wrap">
              <span className={`txn-amount ${txn.type}`}>
                {txn.type === 'credit' ? '+' : '-'} ₹ {txn.amount}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
