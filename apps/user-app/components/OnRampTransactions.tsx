
import { AiOutlineMinusCircle, AiOutlinePlusCircle } from "react-icons/ai"
import { Card } from "./card"

export const OnRampTransaction=({transactions}:{
    transactions:{
        userId:Number,
        time:Date,
        amount:number,
        status:string,
        provider:string,
        type:string
    }[]
})=>{
    if(!transactions.length){
        return <Card title="Recent Transactions">
            <div className="text-center pb-8 pt-8">
                No Recent Transactions
            </div>
        </Card>
    }
    return <Card title="Recent Transactions">
        <div className="max-h-48">
            {transactions.slice(-5).reverse().map((t,index)=> <div key={index} className="flex justify-between text-[#ffffff] ">
                <div>
                    <div className="text-md pb-1 flex items-center gap-2">
                        {t.type==="Recieved"?(<AiOutlinePlusCircle/>):(<AiOutlineMinusCircle />)}
                        {t.type} INR
                    </div>
                    <div className="text-[#d1d5db] text-xs pb-3 pl-6">
                        {t.time.toDateString()}
                    </div>
                </div>
                    <div  className="flex flex-col justify-center pr-5">
                        {t.type === "Recieved" ? (
                <div className="text-green-400">+ Rs {t.amount / 100}</div>
              ) : (
                <div className="text-red-600"> - Rs {t.amount / 100}</div>
              )}
                </div>
            </div>)}
        </div>
    </Card>
}