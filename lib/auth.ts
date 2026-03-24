import { NextAuthOptions } from "next-auth"
import CredentialsProvider from "next-auth/providers/credentials"
import { prisma } from "@/lib/prisma"
import bcrypt from "bcryptjs"

export const authOptions: NextAuthOptions = {
    providers: [
        CredentialsProvider({
            name: "Credentials",
            credentials: {
                email: { label: "Email", type: "email" },
                password: { label: "Password", type: "password" }
            },
            async authorize(credentials) {
                if (!credentials?.email || !credentials?.password) {
                    return null
                }

                const user = await prisma.user.findUnique({
                    where: { email: credentials.email }
                })

                if (!user) {
                    return null
                }

                // --- 1. Brute-force protection: Check if account is locked ---
                if (user.lockUntil && user.lockUntil > new Date()) {
                    throw new Error("ACCOUNT_LOCKED")
                }

                // --- 2. Verify Password ---
                const isPasswordValid = await bcrypt.compare(
                    credentials.password,
                    user.password
                )

                if (!isPasswordValid) {
                    // Increment login attempts & lock if needed
                    const newAttempts = user.loginAttempts + 1
                    const lockUntil = newAttempts >= 5 ? new Date(Date.now() + 60 * 60 * 1000) : null // Lock for 1 hour
                    
                    await prisma.user.update({
                        where: { id: user.id },
                        data: { 
                            loginAttempts: newAttempts,
                            lockUntil: lockUntil
                        }
                    })
                    
                    return null
                }

                // --- 3. Success: Reset brute force and login ---
                await prisma.user.update({
                    where: { id: user.id },
                    data: { 
                        loginAttempts: 0, 
                        lockUntil: null
                    }
                })

                return {
                    id: user.id,
                    email: user.email || "",
                    name: user.name || "",
                    role: user.role,
                }
            }
        })
    ],
    callbacks: {
        async jwt({ token, user }) {
            if (user) {
                token.id = user.id
                token.role = user.role
            }
            return token
        },
        async session({ session, token }) {
            if (session?.user) {
                const extendedSession = session as any
                extendedSession.user.id = token.id
                extendedSession.user.role = token.role
            }
            return session
        }
    },
    pages: {
        signIn: "/secret-gate",
    },
    session: {
        strategy: "jwt",
    },
    secret: process.env.NEXTAUTH_SECRET,
}
