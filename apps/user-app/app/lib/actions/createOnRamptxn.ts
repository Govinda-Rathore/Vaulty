"use server";

import { getServerSession } from "next-auth";
import { authOptions } from "../auth";
import prisma from "@repo/db/client";

export async function createOnRampTransaction(
  amount: number,
  provider: string,
  type: string,
) {
  const session = await getServerSession(authOptions);

  if (!session || !session.user) {
    throw new Error("User not authenticated");
  }
  const token = Math.random().toString(); //should come from banking api but we do not have so we are using math.random function to generate it
  const userId = session.user.id;
  if (!userId) {
    return {
      message: "User Not Loged in",
      status: 401,
    };
  }

  await prisma.onRampTransaction.create({
    data: {
      userId: Number(userId),
      amount: amount,
      status: "Success",
      startTime: new Date(),
      provider,
      token: token,
      type: type,
    },
  });

  await prisma.$transaction(async (tx) => {
    await tx.balance.update({
      where: { userId: Number(userId) },
      data: { amount: { increment: amount } },
    });
  });
  return {
    message: "on ramp transaction added",
    status: 200,
  };
}

export async function createOnRampp2pTransaction(
  amount: number,
  recieverNumber: string,
) {
  const session = await getServerSession(authOptions);

  if (!session || !session.user) {
    throw new Error("User not authenticated");
  }
  const token1 = Math.random().toString();
  const token2 = Math.random().toString(); //should come from banking api but we do not have so we are using math.random function to generate it
  const userId = session.user.id;
  if (!userId) {
    return {
      message: "User Not Loged in",
      status: 401,
    };
  }
  const recieverId = await prisma.user.findFirst({
    where: {
      number: recieverNumber,
    },
  });
  if (!recieverId) {
    return {
      message: "Receiver not found",
      status: 404,
    };
  }

  await prisma.onRampTransaction.createMany({
    data: [
      {
        userId: Number(userId),
        amount: amount,
        status: "Success",
        startTime: new Date(),
        provider: "Transfer",
        token: token1,
        type: "Sent",
      },
      {
        userId: recieverId?.id,
        amount: amount,
        status: "Success",
        startTime: new Date(),
        provider: session.user.email as string,
        token: token2,
        type: "Recieved",
      },
    ],
  });

  return {
    message: "on ramp p2p transaction added",
    status: 200,
  };
}
