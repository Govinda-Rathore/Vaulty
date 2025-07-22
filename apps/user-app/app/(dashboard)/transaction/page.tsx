import { getServerSession } from "next-auth";
import { authOptions } from "../../lib/auth";
import prisma from "@repo/db/client";
import { Transaction } from "../../../components/Transaction";

async function getOnrampTransaction() {
  const session = await getServerSession(authOptions);
  const txns = await prisma.onRampTransaction.findMany({
    where: {
      userId: Number(session?.user?.id),
    },
  });
  return txns.map(
    (t: {
      startTime: Date;
      amount: number;
      status: string;
      provider: string;
      type: string;
    }) => ({
      time: t.startTime,
      amount: t.amount,
      status: t.status,
      provider: t.provider,
      type: t.type,
    }),
  );
}

export default async function transaction() {
  const transactions = await getOnrampTransaction();
  return (
    <div className="w-full mt-10 ml-16 mr-16 mb-16">
      <Transaction transactions={transactions} />
    </div>
  );
}
