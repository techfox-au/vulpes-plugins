// Which condition rows the alert editor draws after a source or plugin change.
export function nextConditions(existing, saved, touched, replace) {
  if (replace) return [];
  if (existing.length) return existing;
  return touched ? [] : (saved || []);
}

// Keep a field the selected sources do not list, so the dropdown does not snap to the first item.
export function fieldChoices(fields, current) {
  const choices = (fields || []).map((field) => ({ value: field.path, label: `${field.label} (${field.path})` }));
  if (current && !choices.some((choice) => choice.value === current)) choices.push({ value: current, label: current });
  return choices;
}

export function hasUnknownConditionField(conditions, fields) {
  const known = new Set((fields || []).map((field) => field.path));
  return (conditions || []).some((condition) => !known.has(condition.field));
}

// Minutes typed in the threshold window. An empty box is not 10, and 0 stays 0.
export function thresholdWindowMinutes(raw) {
  if (raw == null || String(raw).trim() === '') return null;
  return Number(raw);
}

// An excluded source already selected on the rule stays enabled so it can be unchecked.
export function sourceCheckboxDisabled(selected, unavailable) {
  return unavailable === true && !selected;
}
