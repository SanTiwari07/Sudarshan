export const mockUser = {
  name: 'Rahul Sharma',
  lastLogin: '13 Aug 2026, 10:30 AM',
  accounts: [
    { id: 'ACC-001', type: 'Savings Account', number: 'XXXX XXXX 1234', balance: 145000.50, currency: 'INR', ifsc: 'HDFC0001234' },
    { id: 'ACC-002', type: 'Current Account', number: 'XXXX XXXX 5678', balance: 25000.00, currency: 'INR', ifsc: 'HDFC0001234' },
    { id: 'ACC-003', type: 'Fixed Deposit', number: 'XXXX XXXX 9012', balance: 500000.00, currency: 'INR', ifsc: 'HDFC0001234' }
  ],
  transactions: [
    { id: 'TXN-001', date: '12 Aug 2026', description: 'Amazon Shopping', amount: -1250.00, type: 'debit', category: 'Shopping' },
    { id: 'TXN-002', date: '10 Aug 2026', description: 'Salary Credit', amount: 85000.00, type: 'credit', category: 'Income' },
    { id: 'TXN-003', date: '08 Aug 2026', description: 'Electricity Bill', amount: -1450.00, type: 'debit', category: 'Utility' },
    { id: 'TXN-004', date: '05 Aug 2026', description: 'Zomato', amount: -450.00, type: 'debit', category: 'Food' },
    { id: 'TXN-005', date: '04 Aug 2026', description: 'Uber Rides', amount: -320.00, type: 'debit', category: 'Travel' },
    { id: 'TXN-006', date: '02 Aug 2026', description: 'Netflix Subscription', amount: -649.00, type: 'debit', category: 'Entertainment' },
    { id: 'TXN-007', date: '01 Aug 2026', description: 'Rent Payment', amount: -25000.00, type: 'debit', category: 'Housing' },
    { id: 'TXN-008', date: '28 Jul 2026', description: 'Grocery Store', amount: -2340.00, type: 'debit', category: 'Shopping' },
    { id: 'TXN-009', date: '25 Jul 2026', description: 'ATM Withdrawal', amount: -5000.00, type: 'debit', category: 'Cash' },
    { id: 'TXN-010', date: '22 Jul 2026', description: 'Dividend Credit', amount: 1250.00, type: 'credit', category: 'Income' },
    { id: 'TXN-011', date: '20 Jul 2026', description: 'Mobile Recharge', amount: -599.00, type: 'debit', category: 'Utility' },
    { id: 'TXN-012', date: '18 Jul 2026', description: 'Swiggy', amount: -380.00, type: 'debit', category: 'Food' },
    { id: 'TXN-013', date: '15 Jul 2026', description: 'Pharmacy', amount: -850.00, type: 'debit', category: 'Medical' },
    { id: 'TXN-014', date: '12 Jul 2026', description: 'BookMyShow', amount: -900.00, type: 'debit', category: 'Entertainment' },
    { id: 'TXN-015', date: '10 Jul 2026', description: 'Salary Credit', amount: 85000.00, type: 'credit', category: 'Income' }
  ],
  payees: [
    { id: 'PAY-1', name: 'Amit Kumar', account: 'XXXX 4321', bank: 'SBI' },
    { id: 'PAY-2', name: 'Priya Singh', account: 'XXXX 8765', bank: 'ICICI' },
    { id: 'PAY-3', name: 'Ravi Patel', account: 'XXXX 1098', bank: 'Axis' },
    { id: 'PAY-4', name: 'Neha Gupta', account: 'XXXX 5432', bank: 'HDFC' }
  ],
  cards: [
    { id: 'CRD-1', type: 'Credit Card', name: 'Regalia Gold', number: 'XXXX XXXX XXXX 4123', limit: 300000, available: 245000 },
    { id: 'CRD-2', type: 'Debit Card', name: 'Millennia', number: 'XXXX XXXX XXXX 8901', status: 'Active' }
  ],
  notifications: [
    { id: 'NOT-1', title: 'Login Alert', message: 'New login from Chrome on Windows.', date: '13 Aug 2026' },
    { id: 'NOT-2', title: 'Bill Due', message: 'Credit card bill of ₹12,450 is due on 15 Aug.', date: '12 Aug 2026' },
    { id: 'NOT-3', title: 'Offer', message: 'Get 10% cashback on Amazon with HDFC Cards.', date: '10 Aug 2026' }
  ]
};
