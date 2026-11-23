export function sendLinkNote(count, passwordLinks, keyLinks) {
  if (passwordLinks && keyLinks) {
    return 'Save these links now. A key-only link carries the decryption key in the # fragment. Share a password separately, and Vulpes never sees it.';
  }
  if (passwordLinks) {
    return count > 1
      ? 'Save these links and share the password separately. Vulpes never sees the password or the unwrapped key.'
      : 'Save this link and share the password separately. Vulpes never sees the password or the unwrapped key.';
  }
  return count > 1
    ? 'Save these links now. The links include the decryption key in the # fragment. Vulpes cannot show the key again.'
    : 'Save this link now. The link includes the decryption key in the # fragment. Vulpes cannot show the key again.';
}

export function collectLinkNote(count, passwordLinks, keyLinks) {
  if (passwordLinks && keyLinks) {
    return 'Save the collect links now. A key-only collect link’s # fragment is your private key. Share a password separately for a password-protected link. Send only the upload links.';
  }
  if (passwordLinks) {
    return count > 1
      ? 'Save the collect links now. Share each password separately. The # fragment is not the private key. Send only the upload links.'
      : 'Save the collect link now. Share the password separately. The # fragment is not the private key. Send only the upload link.';
  }
  return count > 1
    ? 'Save the collect links now. Each collect link’s # fragment is your private key. Send only the upload link.'
    : 'Save the collect link now. Its # fragment is your private key. Send only the upload link.';
}
