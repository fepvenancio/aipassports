import { useState } from 'react';
import AuthGate from './components/Pages/AuthGate';
import Dashboard from './components/Pages/Dashboard';
import type { AuthSession } from './api/types';

export default function App() {
  const [session, setSession] = useState<AuthSession | null>(null);

  return session ? (
    <Dashboard session={session} onLock={() => setSession(null)} />
  ) : (
    <AuthGate onSuccess={setSession} />
  );
}
