const fs = require('fs');
const path = require('path');

const srcDir = path.join(__dirname, 'src', 'screens');
if (!fs.existsSync(srcDir)) fs.mkdirSync(srcDir, { recursive: true });

const mockAccounts = `
export const MOCK_ACCOUNTS = [
  { id: '1', type: 'Savings Account', number: 'XXXXXX4321', balance: '₹ 45,678.90' },
  { id: '2', type: 'Current Account', number: 'XXXXXX9876', balance: '₹ 1,23,456.00' }
];
`;

const mockTxns = `
export const MOCK_TXNS = [
  { id: 't1', date: '12 Aug 2026', desc: 'Amazon Pay', amount: '-₹ 500.00', type: 'debit' },
  { id: 't2', date: '10 Aug 2026', desc: 'Salary', amount: '+₹ 50,000.00', type: 'credit' },
  { id: 't3', date: '08 Aug 2026', desc: 'Swiggy', amount: '-₹ 320.00', type: 'debit' }
];
`;

const MOCK_DATA = mockAccounts + mockTxns;
fs.writeFileSync(path.join(srcDir, 'mockData.ts'), MOCK_DATA);

const components = {
  'Accounts.tsx': `
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { MOCK_ACCOUNTS } from './mockData';

const Accounts: React.FC = () => {
  const navigate = useNavigate();
  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)' }}>
      <h2 style={{ color: 'var(--color-primary)' }}>My Accounts</h2>
      {MOCK_ACCOUNTS.map(acc => (
        <div key={acc.id} 
             onClick={() => navigate('/accounts/' + acc.id)}
             style={{
               backgroundColor: 'var(--color-surface)', padding: 'var(--space-16)',
               borderRadius: 'var(--radius-card)', boxShadow: 'var(--elevation-1)',
               cursor: 'pointer'
             }}>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>{acc.type}</p>
          <h3 style={{ margin: 'var(--space-4) 0' }}>{acc.balance}</h3>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>A/C: {acc.number}</p>
        </div>
      ))}
    </div>
  );
};
export default Accounts;
  `,
  'AccountDetails.tsx': `
import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { MOCK_ACCOUNTS } from './mockData';
import { Button } from '../components/primitives/Button';

const AccountDetails: React.FC = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const acc = MOCK_ACCOUNTS.find(a => a.id === id) || MOCK_ACCOUNTS[0];

  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)' }}>
      <button onClick={() => navigate(-1)} style={{alignSelf: 'flex-start', background:'none', border:'none', color:'var(--color-primary)', cursor:'pointer'}}>← Back</button>
      <h2 style={{ color: 'var(--color-primary)' }}>Account Details</h2>
      <div style={{
        backgroundColor: 'var(--color-primary)', color: 'var(--color-surface)', padding: 'var(--space-24)',
        borderRadius: 'var(--radius-card)', boxShadow: 'var(--elevation-1)'
      }}>
        <p style={{ fontSize: '0.875rem', opacity: 0.9 }}>{acc.type}</p>
        <h3 style={{ margin: 'var(--space-8) 0', fontSize: '1.5rem' }}>{acc.balance}</h3>
        <p style={{ fontSize: '0.875rem', opacity: 0.9 }}>A/C: {acc.number}</p>
      </div>
      <Button variant="outline" onClick={() => navigate('/accounts/' + acc.id + '/transactions')} fullWidth>
        View Transactions
      </Button>
    </div>
  );
};
export default AccountDetails;
  `,
  'TxnHistory.tsx': `
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { MOCK_TXNS } from './mockData';

const TxnHistory: React.FC = () => {
  const navigate = useNavigate();
  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)' }}>
      <button onClick={() => navigate(-1)} style={{alignSelf: 'flex-start', background:'none', border:'none', color:'var(--color-primary)', cursor:'pointer'}}>← Back</button>
      <h2 style={{ color: 'var(--color-primary)' }}>Transaction History</h2>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-12)' }}>
        {MOCK_TXNS.map(txn => (
          <div key={txn.id} style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            backgroundColor: 'var(--color-surface)', padding: 'var(--space-16)',
            borderRadius: 'var(--radius-card)', boxShadow: 'var(--elevation-1)'
          }}>
            <div>
              <p style={{ fontWeight: 600 }}>{txn.desc}</p>
              <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.75rem' }}>{txn.date}</p>
            </div>
            <p style={{ color: txn.type === 'credit' ? 'var(--color-success)' : 'var(--color-text-primary)', fontWeight: 600 }}>
              {txn.amount}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
};
export default TxnHistory;
  `,
  'Transfer.tsx': `
import React from 'react';
import { useNavigate } from 'react-router-dom';

const Transfer: React.FC = () => {
  const navigate = useNavigate();
  const payees = [{ id: 'p1', name: 'John Doe', acc: 'XXXXXX1111' }, { id: 'p2', name: 'Jane Smith', acc: 'XXXXXX2222' }];
  
  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)' }}>
      <h2 style={{ color: 'var(--color-primary)' }}>Transfer Money</h2>
      <h3>Select Payee</h3>
      {payees.map(p => (
        <div key={p.id} onClick={() => navigate('/transfer/amount')} style={{
          backgroundColor: 'var(--color-surface)', padding: 'var(--space-16)',
          borderRadius: 'var(--radius-card)', boxShadow: 'var(--elevation-1)', cursor: 'pointer'
        }}>
          <p style={{ fontWeight: 600 }}>{p.name}</p>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>{p.acc}</p>
        </div>
      ))}
    </div>
  );
};
export default Transfer;
  `,
  'Amount.tsx': `
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';
import { InputField } from '../components/primitives/InputField';

const Amount: React.FC = () => {
  const navigate = useNavigate();
  const [amount, setAmount] = useState('');
  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)', height: '100%' }}>
      <button onClick={() => navigate(-1)} style={{alignSelf: 'flex-start', background:'none', border:'none', color:'var(--color-primary)', cursor:'pointer'}}>← Back</button>
      <h2 style={{ color: 'var(--color-primary)' }}>Enter Amount</h2>
      <div style={{ flex: 1 }}>
        <InputField label="Amount (₹)" type="number" value={amount} onChange={e => setAmount(e.target.value)} placeholder="0.00" />
      </div>
      <Button variant="primary" fullWidth onClick={() => navigate('/transfer/review')} disabled={!amount}>Continue</Button>
    </div>
  );
};
export default Amount;
  `,
  'Review.tsx': `
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';

const Review: React.FC = () => {
  const navigate = useNavigate();
  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)', height: '100%' }}>
      <button onClick={() => navigate(-1)} style={{alignSelf: 'flex-start', background:'none', border:'none', color:'var(--color-primary)', cursor:'pointer'}}>← Back</button>
      <h2 style={{ color: 'var(--color-primary)' }}>Review Transfer</h2>
      <div style={{ flex: 1, backgroundColor: 'var(--color-surface)', padding: 'var(--space-16)', borderRadius: 'var(--radius-card)' }}>
        <p style={{ color: 'var(--color-text-secondary)' }}>To: John Doe</p>
        <p style={{ color: 'var(--color-text-secondary)' }}>Amount:</p>
        <h3 style={{ fontSize: '1.5rem', margin: 'var(--space-8) 0' }}>₹ 500.00</h3>
      </div>
      <Button variant="primary" fullWidth onClick={() => navigate('/transfer/receipt')}>Confirm Transfer</Button>
    </div>
  );
};
export default Review;
  `,
  'Receipt.tsx': `
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';

const Receipt: React.FC = () => {
  const navigate = useNavigate();
  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)', height: '100%', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ width: 64, height: 64, borderRadius: '50%', backgroundColor: 'var(--color-success)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', fontSize: '32px', marginBottom: 'var(--space-16)' }}>✓</div>
      <h2 style={{ color: 'var(--color-success)' }}>Transfer Successful</h2>
      <p style={{ color: 'var(--color-text-secondary)' }}>₹ 500.00 sent to John Doe</p>
      <div style={{ marginTop: 'auto', width: '100%' }}>
        <Button variant="primary" fullWidth onClick={() => navigate('/home')}>Back to Home</Button>
      </div>
    </div>
  );
};
export default Receipt;
  `,
  'Profile.tsx': `
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';

const Profile: React.FC = () => {
  const navigate = useNavigate();
  return (
    <div style={{ padding: 'var(--space-16)', display: 'flex', flexDirection: 'column', gap: 'var(--space-16)' }}>
      <h2 style={{ color: 'var(--color-primary)' }}>Profile</h2>
      <div style={{ backgroundColor: 'var(--color-surface)', padding: 'var(--space-16)', borderRadius: 'var(--radius-card)', boxShadow: 'var(--elevation-1)' }}>
        <h3 style={{ marginBottom: 'var(--space-4)' }}>John Doe</h3>
        <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>john.doe@example.com</p>
        <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>+91 9876543210</p>
      </div>
      <div style={{ marginTop: 'var(--space-24)' }}>
        <Button variant="outline" fullWidth onClick={() => navigate('/login')}>Logout</Button>
      </div>
    </div>
  );
};
export default Profile;
  `
};

for (const [file, content] of Object.entries(components)) {
  fs.writeFileSync(path.join(srcDir, file), content.trim());
}
console.log('Screens generated.');
