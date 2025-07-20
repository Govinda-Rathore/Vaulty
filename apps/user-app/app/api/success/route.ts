import { NextRequest, NextResponse } from "next/server";
import { createOnRampTransaction } from "../../lib/actions/createOnRamptxn";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { amount, provider } = body;

    if (!amount || !provider) {
      return NextResponse.json(
        { success: false, message: "Missing amount or provider" },
        { status: 400 }
      );
    }

    await createOnRampTransaction(Number(amount), provider, "Recieved");
    return NextResponse.json(
      { success: true },
      { status: 200 }
    );
  } catch (error: any) {
    console.error("Error in /api/success:", error);
    return NextResponse.json(
      { success: false, message: error.message },
      { status: 500 }
    );
  }
}
