// 5. The model can look things up; refunds need a human.
import { streamText, tool } from "ai";
import { openai } from "@ai-sdk/openai";
import { z } from "zod";
import { auth } from "@/auth";
import { getOrderFor, queueRefundRequest } from "@/lib/orders";

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { messages } = await req.json();
  const result = streamText({
    model: openai("gpt-4o"),
    system: "You are a support assistant.",
    messages,
    tools: {
      lookupOrder: tool({ parameters: z.object({ orderId: z.string() }), execute: async ({ orderId }) => getOrderFor(session.user.id, orderId) }),
      requestRefund: tool({
        needsApproval: true,
        parameters: z.object({ orderId: z.string() }),
        execute: async ({ orderId }) => queueRefundRequest(session.user.id, orderId),
      }),
    },
  });
  return result.toDataStreamResponse();
}
