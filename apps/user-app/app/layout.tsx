import "./globals.css";
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { Bounce, ToastContainer } from "react-toastify";
import { AppbarClient } from "../components/AppbarClient";
import { Providers } from "../provider";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Wallet",
  description: "Simple wallet app",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}): React.JSX.Element {
  return (
    <html lang="en">
      <Providers>
        <body className={inter.className}>
          <div className="UniversalBackground overflow-hidden font-inter">
            <AppbarClient />
            {children}
            <ToastContainer
              position="top-center"
              autoClose={3000}
              hideProgressBar={false}
              newestOnTop={false}
              closeOnClick={false}
              rtl={false}
              pauseOnFocusLoss
              draggable
              pauseOnHover
              theme="light"
              transition={Bounce}
            />
          </div>
        </body>
      </Providers>
    </html>
  );
}
