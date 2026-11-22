// 4. The browser talks to our server; the API key never leaves it.
"use client";

export async function ask(question: string) {
  const res = await fetch("/api/support", { method: "POST", body: JSON.stringify({ messages: [{ role: "user", content: question }] }) });
  return res.text();
}
