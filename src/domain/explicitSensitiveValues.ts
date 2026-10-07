/** Replace caller-declared literal text values without guessing sensitivity from names. */
export const redactExplicitText = (
  value: string,
  sensitiveValues: readonly string[],
): string => {
  let result = value;
  for (const literal of [...sensitiveValues].sort(
    (left, right) => right.length - left.length,
  ))
    if (literal !== "") result = result.replaceAll(literal, "[REDACTED]");
  return result;
};
