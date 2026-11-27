export function showAllAlerts(roles) {
  return (roles || []).some((role) => role === 'Admin' || role === 'Analyst');
}
