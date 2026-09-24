export const mockAccounts = [
  {
    id: 'a1',
    type: 'Savings Account',
    accountNumber: '**** **** 1234',
    balance: 145000.50,
    currency: '₹',
    status: 'Active'
  },
  {
    id: 'a2',
    type: 'Current Account',
    accountNumber: '**** **** 5678',
    balance: 54000.00,
    currency: '₹',
    status: 'Active'
  }
];

export const mockTransactions = [
  {
    id: 't1',
    accountId: 'a1',
    date: '2026-08-10',
    description: 'UPI/Zomato',
    amount: -450.00,
    type: 'debit',
    category: 'Food'
  },
  {
    id: 't2',
    accountId: 'a1',
    date: '2026-08-09',
    description: 'Salary Credit',
    amount: 120000.00,
    type: 'credit',
    category: 'Salary'
  },
  {
    id: 't3',
    accountId: 'a1',
    date: '2026-08-05',
    description: 'Electricity Bill',
    amount: -1500.00,
    type: 'debit',
    category: 'Utilities'
  },
  {
    id: 't4',
    accountId: 'a2',
    date: '2026-08-08',
    description: 'Vendor Payment',
    amount: -15000.00,
    type: 'debit',
    category: 'Business'
  }
];

export const mockPayees = [
  {
    id: 'p1',
    name: 'Rahul Sharma',
    accountNumber: '**** 9876',
    bank: 'HDFC Bank'
  },
  {
    id: 'p2',
    name: 'Priya Singh',
    accountNumber: '**** 4321',
    bank: 'ICICI Bank'
  }
];

export const mockUser = {
  name: 'Aditya Verma',
  lastLogin: '12 Aug 2026, 14:30'
};
