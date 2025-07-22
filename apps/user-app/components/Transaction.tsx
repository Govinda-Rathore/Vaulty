import { AiOutlineMinusCircle, AiOutlinePlusCircle } from "react-icons/ai";
import { Card } from "./card";

export const Transaction = ({
  transactions,
}: {
  transactions: {
    time: Date;
    amount: number;
    status: string;
    provider: string;
    type: string;
  }[];
}) => {
  if (!transactions.length) {
    return (
      <Card title="Recent Transactions">
        <div className="text-center pb-8 pt-8">No Transactions</div>
      </Card>
    );
  }
  return (
    <Card title="All Transactions">
      <div className="text-xl">
        {transactions.reverse().map((t, index) => (
          <div key={index} className="flex justify-between text-[#ffffff] ">
            <div>
              <div className=" pb-2 flex items-center gap-2">
                {t.type === "Recieved" ? (
                  <AiOutlinePlusCircle />
                ) : (
                  <AiOutlineMinusCircle />
                )}
                {t.type} INR
              </div>
              <div className="text-[#d1d5db] text-xs pb-6 pl-6">
                {t.time.toDateString()}
              </div>
            </div>
            <div className="flex flex-col justify-center pr-5">
              {t.type === "Recieved" ? (
                <div className="text-green-400">+ Rs {t.amount / 100}</div>
              ) : (
                <div className="text-red-600"> - Rs {t.amount / 100}</div>
              )}
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
};
