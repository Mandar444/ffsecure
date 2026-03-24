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
                password: { label: "Password", type: "password" },
                otp: { label: "OTP Code", type: "text" }
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

                // --- 3. OTP verification (Step 2) ---
                if (credentials.otp) {
                    if (!user.otpCode || !user.otpExpires || user.otpExpires < new Date()) {
                        throw new Error("OTP_EXPIRED")
                    }
                    if (user.otpCode !== credentials.otp) {
                        throw new Error("INVALID_OTP")
                    }

                    // Reset brute force count and OTP on success
                    await prisma.user.update({
                        where: { id: user.id },
                        data: { 
                            loginAttempts: 0, 
                            lockUntil: null, 
                            otpCode: null, 
                            otpExpires: null 
                        }
                    })

                    return {
                        id: user.id,
                        email: user.email || "",
                        name: user.name || "",
                        role: user.role,
                    }
                }

                // --- 4. Password is correct but no OTP: Generate and send OTP (Step 1) ---
                const otp = Math.floor(100000 + Math.random() * 900000).toString()
                await prisma.user.update({
                    where: { id: user.id },
                    data: { 
                        otpCode: otp, 
                        otpExpires: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
                    }
                })

                // Send email (async)
                const { sendOTPEmail } = await import("@/lib/email-service")
                await sendOTPEmail(user.email, otp)

                throw new Error("OTP_REQUIRED")
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
