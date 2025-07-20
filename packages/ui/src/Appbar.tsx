import { MdPayment } from "react-icons/md";
import { Button } from "./button";


interface AppbarProps {
    user?: {
        name?: string | null;
    },
    // TODO: can u figure out what the type should be here?
    onSignin: ()=>void,
    onSignout:()=>void
}

export const Appbar = ({
    user,
    onSignin,
    onSignout
}: AppbarProps) => {
    return <div className="flex justify-between border-b px-4">
        <div className=" flex items-center justify-center text-white text-2xl gap-2">
            <MdPayment/>
            Vaulty
        </div>
        <div className="flex flex-col justify-center pt-2">
            <Button onClick={user ? onSignout : onSignin}>{user ? "Logout" : "Login"}</Button>
        </div>
    </div>
}