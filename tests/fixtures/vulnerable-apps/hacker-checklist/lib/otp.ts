// 11. Guess the login code — a predictable 6-digit code...
export function generateLoginCode(): string {
  const code = Math.floor(100000 + Math.random() * 900000);
  return String(code);
}
