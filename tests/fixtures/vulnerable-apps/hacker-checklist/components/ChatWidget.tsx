// 4. API key in the browser — the OpenAI key ships in the client bundle.
"use client";
import OpenAI from "openai";

const client = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });

export async function ask(question: string) {
  return client.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: question }] });
}
