"use server"

import { getServerSession } from "next-auth"
import { authOptions } from "../auth";
import prisma from "@repo/db/client";

export async function p2pTransfer(to: string, amount: number) {
    const session = await getServerSession(authOptions);
    const from = session?.user?.id;

    if (!from) {
        return {
            message: "User Not Logged In",
            status: 401
        };
    }

    const toUser = await prisma.user.findFirst({
        where: {
            number: to
        }
    });

    if (!toUser) {
        return {
            message: "Reciever not found",
            status: 404
        };
    }

    const fromBalance = await prisma.balance.findUnique({
        where: { userId: Number(from) },
    });

    if (!fromBalance || fromBalance.amount < amount) {
        return {
            message: "Insufficient balance",
            status: 402
        };
    }

    await prisma.$transaction(async (tx:any) => {
        await tx.balance.update({
            where: { userId: Number(from) },
            data: { amount: { decrement: amount } },
        });

        await tx.balance.upsert({
            where: { userId: toUser.id },
            update: { amount: { increment: amount } },
            create: {
               userId: toUser.id,
               amount: amount,
               locked:0,
        },
        
});
    });

    return {
        message: "Transfer successful",
        status: 200
    };
    
}
