// app/bank-redirect/page.tsx

"use client"

import { useEffect } from "react"
import { useRouter, useSearchParams } from "next/navigation"

export default function BankRedirect() {
  const router = useRouter();
  const params = useSearchParams();
  const amount = params.get("amount");
  const provider = params.get("provider");

  useEffect(() => {
    const timer = setTimeout(async () => {
      const result=await fetch("/api/success", {
        method: "POST",
        body: JSON.stringify({ amount, provider })
      });
      const data=await result.json();
      console.log(data.success);
      if(data.success){
        router.push(`/transfer?status=success`)
      }
    }
    , 7000);

    return (() => {
      clearTimeout(timer)
    })
  }, []);

  return (
    <div className="flex flex-col items-center justify-center h-screen text-white font-semibold">
      <h1 className="text-2xl">Redirecting to {provider}...</h1>
      <p className="text-sm mt-4">Don't go back until your payment of Rs {Number(amount)/100 } is Processing</p>
    </div>

  );
}
