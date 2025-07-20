"use client"

import { usePathname } from "next/navigation";
import { useRouter } from "next/navigation"
export const SidebarItem=({href,title,icon}:{href:string,title:string,icon:React.ReactNode})=>{
   
    const router = useRouter();
    const pathname = usePathname();
    const selected = pathname === href;
    return <div className={`flex ${selected ?  "text-white text-xl" : "text-[#d1d5db]"} p-3 pl-8 hover:text-lg cursor-pointer`} onClick={() => {
        router.push(href);
    }}>
        <div className="pr-2">
            {icon}
        </div>
        <div className={`font-bold ${selected ? "text-white text-xl" : "text-[#d1d5db]" }  `}>
            {title}
        </div>
    </div>
}