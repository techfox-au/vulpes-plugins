/** Blank when either JavaScript trim or .NET whitespace would remove the whole name. */
export function rejectedFileName(name) {
  if (name == null || name === '') return '';
  const shown = String(name).replace(/\u0085|\uFEFF/g, '').trim();
  if (shown.length === 0) return 'Enter a file name.';
  if (shown.length > 200) return 'File name is too long (max 200 characters).';
  return '';
}
