export const MOCK_USER = {
  name: "Sudarshan Reddy",
  lastLogin: "12 Aug 2026, 10:30 AM",
};

export const MOCK_ACCOUNTS = [
  {
    id: "acc-01",
    type: "Savings Account",
    accountNumber: "XXXX XXXX 1234",
    balance: 145000.50,
    currency: "₹",
  },
  {
    id: "acc-02",
    type: "Current Account",
    accountNumber: "XXXX XXXX 5678",
    balance: 50000.00,
    currency: "₹",
  }
];

export const MOCK_TRANSACTIONS = [
  {
    id: "txn-01",
    date: "12 Aug 2026",
    description: "UPI/Zomato/Food",
    amount: -450.00,
    type: "DEBIT",
    status: "SUCCESS"
  },
  {
    id: "txn-02",
    date: "11 Aug 2026",
    description: "NEFT/Salary/Tech Corp",
    amount: 85000.00,
    type: "CREDIT",
    status: "SUCCESS"
  },
  {
    id: "txn-03",
    date: "10 Aug 2026",
    description: "POS/Reliance Fresh",
    amount: -1250.75,
    type: "DEBIT",
    status: "SUCCESS"
  },
  {
    id: "txn-04",
    date: "09 Aug 2026",
    description: "IMPS/Transfer to Anil",
    amount: -5000.00,
    type: "DEBIT",
    status: "SUCCESS"
  }
];

export const MOCK_SERVICES = [
  { id: 'srv-1', title: 'Debit Card Services', icon: 'credit-card' },
  { id: 'srv-2', title: 'Cheque Book Request', icon: 'book' },
  { id: 'srv-3', title: 'FD/RD Opening', icon: 'piggy-bank' },
  { id: 'srv-4', title: 'Update KYC', icon: 'user-check' }
];
