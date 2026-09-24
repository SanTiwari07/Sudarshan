
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';

import { Splash } from './screens/Splash';
import { Login } from './screens/Login';
import { MPIN } from './screens/MPIN';
import { Home } from './screens/Home';
import { Accounts } from './screens/Accounts';
import { Transfer } from './screens/Transfer';
import { Amount } from './screens/Amount';
import { Review } from './screens/Review';
import { Receipt } from './screens/Receipt';

// Dummy screens for App Shell setup
const PlaceholderScreen = ({ title }: { title: string }) => (
  <div style={{ padding: '24px', textAlign: 'center' }}>
    <h2>{title}</h2>
    <p>This screen is under construction.</p>
  </div>
);

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route path="/" element={<Navigate to="/splash" replace />} />
          <Route path="/splash" element={<Splash />} />
          <Route path="/login" element={<Login />} />
          <Route path="/mpin" element={<MPIN />} />
          <Route path="/home" element={<Home />} />
          <Route path="/accounts" element={<Accounts />} />
          <Route path="/transfer" element={<Transfer />} />
          <Route path="/transfer/amount" element={<Amount />} />
          <Route path="/transfer/review" element={<Review />} />
          <Route path="/transfer/receipt" element={<Receipt />} />
          <Route path="/services" element={<PlaceholderScreen title="SERVICES" />} />
          <Route path="/profile" element={<PlaceholderScreen title="PROFILE" />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
