// app/bank-redirect/page.tsx

import { Suspense } from "react";
import BankRedirect from "./BankRedirectPage";

export default function Page() {
  return (
    <Suspense fallback={<div className="text-white p-10">Processing...</div>}>
      <BankRedirect />
    </Suspense>
  );
}
