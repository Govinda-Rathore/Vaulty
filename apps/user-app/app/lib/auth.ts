import { NextAuthOptions, Session } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { JWT } from "next-auth/jwt";
import bcrypt from "bcrypt";
import db from "@repo/db/client";

interface Credentials {
  phone: string;
  password: string;
}

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        phone: {
          label: "Phone number",
          type: "text",
          placeholder: "1231231231",
          required: true,
        },
        password: { label: "Password", type: "password", required: true },
      },
      async authorize(credentials: Credentials | undefined) {
        if (!credentials) return null;

        const { phone, password } = credentials;

        const existingUser = await db.user.findFirst({
          where: { number: phone },
        });

        if (existingUser) {
          const passwordValid = await bcrypt.compare(
            password,
            existingUser.password,
          );

          if (passwordValid) {
            return {
              id: existingUser.id.toString(),
              name: existingUser.name,
              email: existingUser.number,
            };
          }

          return null;
        }

        // Create new user
        const hashedPassword = await bcrypt.hash(password, 10);
        try {
          const user = await db.user.create({
            data: {
              number: phone,
              password: hashedPassword,
            },
          });

          await db.balance.create({
            data: {
              userId: user.id,
              amount: 0,
              locked: 0,
            },
          });

          return {
            id: user.id.toString(),
            name: user.name,
            email: user.number,
          };
        } catch (e) {
          console.error(e);
          return null;
        }
      },
    }),
  ],
  secret: process.env.JWT_SECRET || "secret",
  callbacks: {
    async session({ token, session }: { token: JWT; session: Session }) {
      session.user.id = token.sub!;
      return session;
    },
  },
};
