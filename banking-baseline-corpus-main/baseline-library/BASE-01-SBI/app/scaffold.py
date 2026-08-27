import os
import json

base_dir = r"f:\banking-baseline-corpus\baseline-library\BASE-01-SBI\app\src"
screens_dir = os.path.join(base_dir, "screens")

screens = {
    "Splash.tsx": """import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export const Splash: React.FC = () => {
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setTimeout(() => {
      navigate('/login');
    }, 1500);
    return () => clearTimeout(timer);
  }, [navigate]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', justifyContent: 'center', alignItems: 'center', backgroundColor: 'var(--color-primary, #1B4AA0)', color: 'white' }}>
      <h1>YONO</h1>
      <p>You Only Need One</p>
    </div>
  );
};
""",
    "Login.tsx": """import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/primitives/Button';
import { InputField } from '../components/primitives/InputField';

export const Login: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <div style={{ flex: 1 }}>
        <h1 style={{ color: 'var(--color-primary)', textAlign: 'center', marginBottom: '32px' }}>YONO SBI</h1>
        <InputField label="Username" placeholder="Enter username" />
        <InputField label="Password" type="password" placeholder="Enter password" />
        <div style={{ marginTop: '24px' }}>
          <Button fullWidth onClick={() => navigate('/mpin')}>Login</Button>
        </div>
      </div>
      <div style={{ textAlign: 'center' }}>
        <Button variant="outline" fullWidth onClick={() => {}}>Forgot MPIN?</Button>
        <p style={{ marginTop: '16px', color: 'var(--color-text-secondary)' }}>New user? Register</p>
      </div>
    </div>
  );
};
""",
    "MPIN.tsx": """import React from 'react';
import { useNavigate } from 'react-router-dom';
import { PINPad } from '../components/primitives/PINPad';

export const MPIN: React.FC = () => {
  const navigate = useNavigate();

  const handleComplete = (pin: string) => {
    navigate('/home');
  };

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <h2 style={{ textAlign: 'center', marginBottom: '32px' }}>Enter MPIN</h2>
      <div style={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
        <PINPad onComplete={handleComplete} />
      </div>
    </div>
  );
};
""",
    "Home.tsx": """import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { mockUser } from '../data/mockData';
import { Wallet, Send, Menu, User, Bell } from 'lucide-react';

export const Home: React.FC = () => {
  const navigate = useNavigate();
  const mainAccount = mockUser.accounts[0];

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)' }}>
      <Header title="YONO SBI" />
      <div className="page-content" style={{ padding: '16px' }}>
        <h2>Good morning, {mockUser.name}</h2>
        
        {/* Account Summary Card */}
        <div 
          onClick={() => navigate(`/accounts/${mainAccount.id}`)}
          style={{ 
            backgroundColor: 'var(--color-primary)', 
            color: 'white', 
            padding: '20px', 
            borderRadius: '16px',
            marginTop: '16px',
            cursor: 'pointer'
          }}
        >
          <p>Available Balance</p>
          <h3 style={{ fontSize: '24px', margin: '8px 0' }}>{mainAccount.currency} {mainAccount.balance.toFixed(2)}</h3>
          <p>{mainAccount.number}</p>
        </div>

        {/* Quick Actions */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '24px' }}>
          <div onClick={() => navigate('/transfer')} style={{ backgroundColor: 'white', padding: '16px', borderRadius: '12px', textAlign: 'center', cursor: 'pointer' }}>
            <Send color="var(--color-primary)" />
            <p style={{ marginTop: '8px' }}>Transfer</p>
          </div>
          <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '12px', textAlign: 'center', cursor: 'pointer' }}>
            <Wallet color="var(--color-primary)" />
            <p style={{ marginTop: '8px' }}>Pay</p>
          </div>
          <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '12px', textAlign: 'center', cursor: 'pointer' }}>
            <Menu color="var(--color-primary)" />
            <p style={{ marginTop: '8px' }}>Scan & Pay</p>
          </div>
          <div onClick={() => navigate('/services')} style={{ backgroundColor: 'white', padding: '16px', borderRadius: '12px', textAlign: 'center', cursor: 'pointer' }}>
            <User color="var(--color-primary)" />
            <p style={{ marginTop: '8px' }}>Services</p>
          </div>
        </div>

        {/* Recent Activity */}
        <div style={{ marginTop: '24px', backgroundColor: 'white', padding: '16px', borderRadius: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3>Recent Activity</h3>
            <span style={{ color: 'var(--color-primary)', cursor: 'pointer' }} onClick={() => navigate(`/accounts/${mainAccount.id}/transactions`)}>View all</span>
          </div>
          <div style={{ marginTop: '16px' }}>
            {mockUser.transactions.map(txn => (
              <div key={txn.id} style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid var(--color-divider)' }}>
                <div>
                  <p style={{ fontWeight: 500 }}>{txn.description}</p>
                  <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>{txn.date}</p>
                </div>
                <div style={{ color: txn.amount > 0 ? 'var(--color-success)' : 'var(--color-text-primary)' }}>
                  {txn.amount > 0 ? '+' : ''}{txn.amount.toFixed(2)}
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
};
""",
    "Accounts.tsx": """import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { mockUser } from '../data/mockData';

export const Accounts: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)' }}>
      <Header title="Accounts" showBack />
      <div className="page-content" style={{ padding: '16px' }}>
        {mockUser.accounts.map(acc => (
          <div 
            key={acc.id}
            onClick={() => navigate(`/accounts/${acc.id}`)}
            style={{ 
              backgroundColor: 'white', 
              padding: '20px', 
              borderRadius: '16px',
              marginBottom: '16px',
              cursor: 'pointer'
            }}
          >
            <p style={{ color: 'var(--color-text-secondary)' }}>{acc.type}</p>
            <h3 style={{ fontSize: '20px', margin: '8px 0' }}>{acc.currency} {acc.balance.toFixed(2)}</h3>
            <p>{acc.number}</p>
          </div>
        ))}
      </div>
    </div>
  );
};
""",
    "AccountDetails.tsx": """import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';
import { mockUser } from '../data/mockData';

export const AccountDetails: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams();
  const account = mockUser.accounts.find(a => a.id === id) || mockUser.accounts[0];

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)' }}>
      <Header title="Account Details" showBack />
      <div className="page-content" style={{ padding: '16px' }}>
        <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '16px' }}>
          <p style={{ textAlign: 'center', color: 'var(--color-text-secondary)' }}>Available Balance</p>
          <h2 style={{ textAlign: 'center', fontSize: '28px', margin: '16px 0', color: 'var(--color-primary)' }}>
            {account.currency} {account.balance.toFixed(2)}
          </h2>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderTop: '1px solid var(--color-divider)' }}>
            <span>Account Number</span>
            <strong>{account.number}</strong>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderTop: '1px solid var(--color-divider)' }}>
            <span>Account Type</span>
            <strong>{account.type}</strong>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderTop: '1px solid var(--color-divider)' }}>
            <span>IFSC</span>
            <strong>SBIN0001234</strong>
          </div>
        </div>

        <div style={{ marginTop: '24px' }}>
          <Button fullWidth onClick={() => navigate(`/accounts/${account.id}/transactions`)}>View all transactions</Button>
        </div>
      </div>
    </div>
  );
};
""",
    "TxnHistory.tsx": """import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { mockUser } from '../data/mockData';

export const TxnHistory: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams();

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)', height: '100vh', overflowY: 'auto' }}>
      <Header title="Transaction History" showBack />
      <div className="page-content" style={{ padding: '16px' }}>
        <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '16px' }}>
          {mockUser.transactions.map(txn => (
            <div key={txn.id} style={{ display: 'flex', justifyContent: 'space-between', padding: '16px 0', borderBottom: '1px solid var(--color-divider)' }}>
              <div>
                <p style={{ fontWeight: 500 }}>{txn.description}</p>
                <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>{txn.date}</p>
              </div>
              <div style={{ color: txn.amount > 0 ? 'var(--color-success)' : 'var(--color-text-primary)' }}>
                {txn.amount > 0 ? '+' : ''}{txn.amount.toFixed(2)}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
""",
    "Transfer.tsx": """import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';

export const Transfer: React.FC = () => {
  const navigate = useNavigate();

  const payees = [
    { id: '1', name: 'Amit Kumar', bank: 'HDFC Bank', number: 'XXXX1122' },
    { id: '2', name: 'Priya Singh', bank: 'ICICI Bank', number: 'XXXX3344' },
  ];

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)' }}>
      <Header title="Send Money" showBack />
      <div className="page-content" style={{ padding: '16px' }}>
        <h3 style={{ marginBottom: '16px' }}>Select Payee</h3>
        {payees.map(p => (
          <div 
            key={p.id}
            onClick={() => navigate('/transfer/amount')}
            style={{ 
              backgroundColor: 'white', 
              padding: '16px', 
              borderRadius: '12px',
              marginBottom: '12px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}
          >
            <div>
              <p style={{ fontWeight: 'bold' }}>{p.name}</p>
              <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>{p.bank} - {p.number}</p>
            </div>
          </div>
        ))}
        <div style={{ marginTop: '24px' }}>
          <Button fullWidth variant="outline" onClick={() => {}}>+ Add New Payee</Button>
        </div>
      </div>
    </div>
  );
};
""",
    "Amount.tsx": """import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';
import { InputField } from '../components/primitives/InputField';

export const Amount: React.FC = () => {
  const navigate = useNavigate();
  const [amount, setAmount] = useState('');

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)', display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <Header title="Enter Amount" showBack />
      <div className="page-content" style={{ padding: '16px', flex: 1 }}>
        <div style={{ backgroundColor: 'white', padding: '24px', borderRadius: '16px', textAlign: 'center', marginBottom: '24px' }}>
          <p style={{ color: 'var(--color-text-secondary)' }}>Paying Amit Kumar</p>
          <p style={{ fontSize: '12px' }}>HDFC Bank - XXXX1122</p>
        </div>
        
        <InputField 
          label="Amount" 
          placeholder="₹ 0.00" 
          type="number"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
        <InputField 
          label="Add a note (Optional)" 
          placeholder="e.g. Rent" 
        />
      </div>
      <div style={{ padding: '16px', backgroundColor: 'white' }}>
        <Button fullWidth onClick={() => navigate('/transfer/review')}>Continue</Button>
      </div>
    </div>
  );
};
""",
    "Review.tsx": """import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';

export const Review: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)', display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <Header title="Review Transfer" showBack />
      <div className="page-content" style={{ padding: '16px', flex: 1 }}>
        <div style={{ backgroundColor: 'white', padding: '24px', borderRadius: '16px' }}>
          <h2 style={{ textAlign: 'center', marginBottom: '24px', fontSize: '32px' }}>₹ 500.00</h2>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid var(--color-divider)' }}>
            <span style={{ color: 'var(--color-text-secondary)' }}>To</span>
            <strong style={{ textAlign: 'right' }}>Amit Kumar<br/>XXXX1122</strong>
          </div>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid var(--color-divider)' }}>
            <span style={{ color: 'var(--color-text-secondary)' }}>From</span>
            <strong style={{ textAlign: 'right' }}>Savings Account<br/>XXXX 1234</strong>
          </div>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0' }}>
            <span style={{ color: 'var(--color-text-secondary)' }}>Note</span>
            <strong>Gift</strong>
          </div>
        </div>
      </div>
      <div style={{ padding: '16px', backgroundColor: 'white' }}>
        <Button fullWidth onClick={() => navigate('/transfer/confirm')}>Confirm</Button>
      </div>
    </div>
  );
};
""",
    "Confirm.tsx": """import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { PINPad } from '../components/primitives/PINPad';

export const Confirm: React.FC = () => {
  const navigate = useNavigate();

  const handleComplete = () => {
    navigate('/transfer/receipt');
  };

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <Header title="Enter MPIN to Confirm" showBack />
      <div className="page-content" style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}>
        <p style={{ marginBottom: '24px' }}>Please enter your 6-digit MPIN</p>
        <PINPad onComplete={handleComplete} />
      </div>
    </div>
  );
};
""",
    "Receipt.tsx": """import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';

export const Receipt: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', height: '100vh', backgroundColor: 'var(--color-bg)' }}>
      <Header title="Receipt" />
      <div className="page-content" style={{ padding: '24px', flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ width: '64px', height: '64px', borderRadius: '32px', backgroundColor: 'var(--color-success)', color: 'white', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '32px', marginBottom: '24px' }}>
          ✓
        </div>
        <h2 style={{ marginBottom: '8px' }}>Payment successful</h2>
        <p style={{ color: 'var(--color-text-secondary)', marginBottom: '32px' }}>Transaction ID: TXN987654321</p>
        
        <div style={{ backgroundColor: 'white', padding: '24px', borderRadius: '16px', width: '100%' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0' }}>
            <span>To</span>
            <strong>Amit Kumar</strong>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0' }}>
            <span>Amount</span>
            <strong>₹ 500.00</strong>
          </div>
        </div>
      </div>
      <div style={{ padding: '16px', backgroundColor: 'white' }}>
        <Button fullWidth onClick={() => navigate('/home')}>Done</Button>
      </div>
    </div>
  );
};
""",
    "Services.tsx": """import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';

export const Services: React.FC = () => {
  const navigate = useNavigate();
  
  const services = ['Cards', 'Deposits', 'Cheque', 'Requests', 'Support'];

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)' }}>
      <Header title="Services" />
      <div className="page-content" style={{ padding: '16px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
          {services.map(s => (
            <div key={s} style={{ backgroundColor: 'white', padding: '24px', borderRadius: '12px', textAlign: 'center', fontWeight: 'bold' }}>
              {s}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
""",
    "Profile.tsx": """import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Button } from '../components/primitives/Button';
import { mockUser } from '../data/mockData';

export const Profile: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="page-container" style={{ paddingBottom: '70px', backgroundColor: 'var(--color-bg)', height: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Header title="Profile" />
      <div className="page-content" style={{ padding: '16px', flex: 1 }}>
        <div style={{ backgroundColor: 'white', padding: '24px', borderRadius: '16px', textAlign: 'center', marginBottom: '24px' }}>
          <div style={{ width: '80px', height: '80px', borderRadius: '40px', backgroundColor: 'var(--color-primary)', color: 'white', margin: '0 auto 16px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '32px' }}>
            {mockUser.name.charAt(0)}
          </div>
          <h2>{mockUser.name}</h2>
          <p style={{ color: 'var(--color-text-secondary)' }}>Last login: {mockUser.lastLogin}</p>
        </div>
        
        <div style={{ backgroundColor: 'white', borderRadius: '16px', padding: '8px 16px' }}>
          <div style={{ padding: '16px 0', borderBottom: '1px solid var(--color-divider)' }}>Settings</div>
          <div style={{ padding: '16px 0' }}>Security</div>
        </div>

        <div style={{ marginTop: '32px' }}>
          <Button variant="outline" fullWidth onClick={() => navigate('/login')}>Logout</Button>
        </div>
      </div>
    </div>
  );
};
"""
}

for name, content in screens.items():
    with open(os.path.join(screens_dir, name), 'w', encoding='utf-8') as f:
        f.write(content)

print("Screens created successfully.")
