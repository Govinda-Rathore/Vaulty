"use client"

import { LuSquareDot } from "react-icons/lu";

export const TextInput=({
    placeholder,
    onChange
}:{placeholder:string;
    onChange:(value:string)=>void;
})=>{
    return<div className="pt-2">
        <input onChange={(e)=>onChange(e.target.value)} type="text" id="first_name" className="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5" placeholder={placeholder} />
    </div>
}