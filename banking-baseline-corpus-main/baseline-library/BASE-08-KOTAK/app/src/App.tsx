import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';

import Splash from './screens/Splash';
import Login from './screens/Login';
import MPIN from './screens/MPIN';
import Home from './screens/Home';
import Accounts from './screens/Accounts';
import AccountDetails from './screens/AccountDetails';
import TxnHistory from './screens/TxnHistory';
import Transfer from './screens/Transfer';
import Amount from './screens/Amount';
import Review from './screens/Review';
import Receipt from './screens/Receipt';
import Profile from './screens/Profile';
import Services from './screens/Services';

const Scan = () => <div className="p-4 flex flex-col min-h-screen bg-gray-50"><h1 className="text-xl">Scan QR Placeholder</h1></div>;

const App: React.FC = () => {
  useEffect(() => {
    // Add logic to hide splash screen natively if needed
  }, []);

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/splash" element={<Splash />} />
        <Route path="/login" element={<Login />} />
        <Route path="/mpin" element={<MPIN />} />
        
        {/* AppShell provides bottom navigation and layout wrapper */}
        <Route element={<AppShell />}>
          <Route path="/home" element={<Home />} />
          <Route path="/accounts" element={<Accounts />} />
          <Route path="/accounts/details" element={<AccountDetails />} />
          <Route path="/transactions" element={<TxnHistory />} />
          <Route path="/scan" element={<Scan />} />
          <Route path="/transfer" element={<Transfer />} />
          <Route path="/transfer/amount" element={<Amount />} />
          <Route path="/transfer/review" element={<Review />} />
          <Route path="/transfer/receipt" element={<Receipt />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/services" element={<Services />} />
        </Route>

        <Route path="/" element={<Navigate to="/splash" replace />} />
      </Routes>
    </BrowserRouter>
  );
};

export default App;
