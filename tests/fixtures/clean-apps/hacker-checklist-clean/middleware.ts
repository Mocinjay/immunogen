// Global rate limit for every API route (login, sign-up, code verification, AI chat).
import { Ratelimit } from "@upstash/ratelimit";
import { NextResponse, type NextRequest } from "next/server";

const ratelimit = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(10, "1 m") });

export default async function middleware(req: NextRequest) {
  const { success } = await ratelimit.limit(req.ip ?? "anonymous");
  return success ? NextResponse.next() : new NextResponse("Too many requests", { status: 429 });
}

export const config = { matcher: "/api/:path*" };
