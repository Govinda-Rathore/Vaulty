
import { GiPadlock, GiPadlockOpen } from "react-icons/gi";
import { MdOutlineAccountBalance, MdOutlineAccountBalanceWallet } from "react-icons/md";
import { Card } from "./card";

export const BalanceCard=({amount,locked}:{
    amount:number;
    locked:number;
})=>{
    return <Card title="Balance">
        <div className="flex justify-between border-slate-300 pb-2  ">
            <div className="text-[#d1d5db] flex gap-1 items-center">
                <GiPadlockOpen/>
                Unlocked Balance
            </div>
            <div className="text-[#d1d5db]">
                {amount/100} INR
            </div>
        </div>
        <div className="flex justify-between border-slate-300 py-2">
            <div className="text-[#d1d5db] flex gap-1 items-center">
                <GiPadlock/>
                Total locked 
            </div>
            <div className="text-[#d1d5db]">
                {locked/100} INR
            </div>
        </div>
        <div className="flex justify-between border-slate-300 py-2">
            <div className="text-[#d1d5db] flex gap-1 items-center">
            <MdOutlineAccountBalanceWallet/>
                Total Balance
            </div>
            <div className="text-[#d1d5db]">
                {(locked + amount) / 100} INR
            </div>
        </div>

    </Card>
}