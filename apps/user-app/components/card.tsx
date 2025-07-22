import React from "react";

export function Card({
  title,
  children,
}: {
  title: string;
  children?: React.ReactNode;
}): React.JSX.Element {
  return (
    <div className="border bg-white/10 backdrop-blur-lg shadow-2xl rounded-2xl p-7 border-white/30 overflow-auto ">
      <h1 className="text-3xl pb-2 mb-6 text-[#ffffff] font-bold ">{title}</h1>

      <div className="text-md font-inter font-semibold">{children}</div>
    </div>
  );
}
