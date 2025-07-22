import React, { JSX } from "react";

function Aa({ children }: { children: React.ReactNode }): JSX.Element {
  return (
    <div className="flex justify-center flex-col h-full">
      <div className="flex justify-center">{children}</div>
    </div>
  );
}

export default Aa;
