// AUTH-01 must NOT fire: the handler checks the session before responding.
import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";

export async function GET() {
  const session = await getServerSession();
  if (!session) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }
  const users = [{ id: 1, name: "fixture-user" }];
  return NextResponse.json(users);
}
