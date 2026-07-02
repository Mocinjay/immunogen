// CONFIG-02: a debug-segment route handler that returns the entire
// environment object to any caller.
import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json(process.env);
}
