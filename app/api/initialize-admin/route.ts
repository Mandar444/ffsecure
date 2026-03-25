import { NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import bcrypt from "bcryptjs"

const MASTER_TOKEN = "FF-ADMIN-2026-SECURE-V1"

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url)
  const token = searchParams.get("token")

  if (token !== MASTER_TOKEN) {
    return new NextResponse("Unauthorized", { status: 401 })
  }

  try {
    const email = "admin@fashionfabric.in"
    const password = "FashionFabric@2026"
    const hashedPassword = await bcrypt.hash(password, 10)

    const user = await prisma.user.upsert({
      where: { email },
      update: {
        password: hashedPassword,
        role: "admin",
        loginAttempts: 0,
        lockUntil: null
      },
      create: {
        email,
        password: hashedPassword,
        role: "admin"
      }
    })

    return NextResponse.json({
      success: true,
      message: `Admin user [${email}] initialized/updated. You can now login.`,
      user: { id: user.id, email: user.email, role: user.role }
    })

  } catch (error: any) {
    return NextResponse.json({
      success: false,
      error: error.message
    }, { status: 500 })
  }
}
