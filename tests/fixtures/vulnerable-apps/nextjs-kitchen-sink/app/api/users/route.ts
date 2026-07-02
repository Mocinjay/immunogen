// AUTH-01: exported Next.js App Router GET handler with no authentication
// or authorization check anywhere in this file.
import { NextResponse } from "next/server";

export async function GET() {
  const users = [{ id: 1, name: "fixture-user" }];
  return NextResponse.json(users);
}
