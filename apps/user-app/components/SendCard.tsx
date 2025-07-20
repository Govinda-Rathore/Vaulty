"use client"

import { Button } from '@repo/ui/button'


import React, { useState } from 'react'
import { p2pTransfer } from '../app/lib/actions/p2pTransfer'
import { createOnRampp2pTransaction } from '../app/lib/actions/createOnRamptxn'

import { ThreeDot } from 'react-loading-indicators'
import { toast } from 'react-toastify'
import { useRouter } from 'next/navigation'
import { TextInput } from '@repo/ui/textinput'
import Aa from '@repo/ui/Aa'
import { useSession } from 'next-auth/react'
import { Card } from './card'



function SendCard() {
    const [number,setNumber]=useState("");
    const [amount,setAmount]=useState("");
    const { data: session } = useSession();
    const [loading,setLoading]=useState(false);
    const router=useRouter();
  return (
    <div className='h-[90vh]'>
        <Aa>
            <Card title='Send Money'>
                <div className='min-w-72 pt-2'>
                    <TextInput placeholder={"Number"}  onChange={(value)=>{
                        setNumber(value);
                    }}/>
                    <TextInput placeholder={"Amount"} onChange={(value)=>{
                        setAmount(value);
                    }}/>
                    <div className='pt-4 flex justify-center'>
                        <Button onClick={async()=>{
                            if(amount==="" && number!=="") {
                                toast.error("Please enter the Amount")
                                return;
                            }
                            else if(amount!=="" && number==="") {
                                toast.error("Please enter the Number")
                                return;
                            }
                            setLoading(true);
                            const p2presult=await p2pTransfer(number,Number(amount)*100)
                            if(p2presult?.status===200){
                                const result=createOnRampp2pTransaction(Number(amount)*100,number);
                                if((await result).status===200){
                                    toast.success("Sent");
                                }
                            }
                            else if(p2presult?.status===401){
                                toast.error("User Not Logged In");
                            }
                            else if(p2presult?.status===404){
                                toast.error("Reciever Not Found");
                            }
                            else if(p2presult?.status===402){
                                toast.error("Insufficient Fund");
                            }
                            else{
                                toast.error("App Server Down");
                            }
                            setTimeout(()=>{
                                setLoading(false);
                                router.refresh();
                            },2000)
                        }}>
                            {loading ? <ThreeDot variant="pulsate" color="#4cc4e8" size="small" text="" textColor="" /> : "Send"}</Button>
                    </div>
                </div>
            </Card>
            </Aa>
    </div>
  )
}

export default SendCard