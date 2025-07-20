"use client"
import { Button } from "@repo/ui/button";

import { useState } from "react";
import { ThreeDot } from "react-loading-indicators";
import { useRouter, useSearchParams } from 'next/navigation';
import { Select } from "@repo/ui/select";
import { TextInput } from "@repo/ui/textinput";
import { Card } from "./card";




const SUPPORTED_BANKS=[{
    name:"HDFC Bank",
    redirectUrl:"/apps/bank-webhook/app/Bank",

},{
    name:"Axis bank",
    redirectUrl:"/apps/bank-webhook/app/Bank",
},{
    name:"ICICI Bank",
    redirectUrl:"apps/bank-webhook/app/Bank",
}
];

export const AddMoney=()=>{
    const [redirectUrl,setredirectUrl]=useState(SUPPORTED_BANKS[0]?.redirectUrl);
    const [amount,setAmount]=useState(0);
    const [provider,setProvider]=useState(SUPPORTED_BANKS[0]?.name||"");
    const [loading,setLoading]=useState(false);
    const router=useRouter();
    return <Card title="Add Money">
        <div className="w-full">
            <div className="pb-6">
            <TextInput placeholder={"Amount"} onChange={(value) => {
                setAmount(parseInt(value));
        }} />
            </div>
        <Select onSelect={(value)=>{
            setredirectUrl(SUPPORTED_BANKS.find(x=>x.name === value)?.redirectUrl||"")
            setProvider(SUPPORTED_BANKS.find(x=> x.name===value)?.name||"")
        }} options={SUPPORTED_BANKS.map(x=>({
            key:x.name,
            value:x.name,
        }))}/>
        <div className="flex justify-center pt-4">
            <Button
             onClick={async ()=>{
                if(amount===0) return;
                setLoading(true),
                setTimeout(()=>{
                    setLoading(false),
                    router.push(`/Bank?amount=${amount*100}&provider=${provider}`);
                    router.refresh();
                },2000);
            }}>
                {loading ? <ThreeDot variant="pulsate" color="#4cc4e8" size="small" text="" textColor="" /> : "Add Money"}</Button>
        </div>
        </div>
    </Card>
}