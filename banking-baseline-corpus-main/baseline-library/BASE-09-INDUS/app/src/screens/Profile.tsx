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
        <Button variant="secondary" fullWidth onClick={() => navigate('/login')}>Logout</Button>
      </div>
    </div>
  );
};
export default Profile;