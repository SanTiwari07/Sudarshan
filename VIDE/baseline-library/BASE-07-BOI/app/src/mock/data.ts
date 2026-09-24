export const mockData = {
  user: {
    name: "Rajesh Kumar",
    lastLogin: "13 Aug 2026, 09:14 AM"
  },
  accounts: [
    {
      id: "acc_1",
      type: "Savings Account",
      accountNumber: "0019 xxxx xxxx 4521",
      balance: 145250.75,
      currency: "INR"
    },
    {
      id: "acc_2",
      type: "Current Account",
      accountNumber: "0019 xxxx xxxx 8892",
      balance: 24500.00,
      currency: "INR"
    }
  ],
  transactions: [
    {
      id: "txn_1",
      date: "12 Aug 2026",
      description: "UPI/Zomato",
      amount: -450.00,
      type: "debit"
    },
    {
      id: "txn_2",
      date: "11 Aug 2026",
      description: "NEFT/Salary",
      amount: 85000.00,
      type: "credit"
    },
    {
      id: "txn_3",
      date: "10 Aug 2026",
      description: "UPI/Grocery",
      amount: -1250.50,
      type: "debit"
    }
  ],
  payees: [
    { id: "p_1", name: "Anjali Singh", account: "xxxx 1234", bank: "HDFC Bank" },
    { id: "p_2", name: "Suresh Patel", account: "xxxx 5678", bank: "SBI" }
  ]
};
