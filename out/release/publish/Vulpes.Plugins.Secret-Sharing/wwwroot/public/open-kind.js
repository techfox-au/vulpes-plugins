export function openKind(pathname, kindParam) {
  const path = String(pathname || '').replace(/\/+$/, '');
  return path.toLowerCase() === '/collect' || kindParam === 'collect' ? 'collect' : 'send';
}
