// 11. Codes come from a CSPRNG.
import { randomInt } from "node:crypto";

export function generateLoginCode(): string {
  return String(randomInt(100000, 1000000));
}
