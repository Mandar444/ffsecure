import { getToken } from "next-auth/jwt"
import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"

// --- STABLE SECURITY CONFIG ---
const SECRET_GATE_PATH = "/secret-gate"
const ACCESS_TOKEN = "FF-ADMIN-2026-SECURE-V1"
const HONEYPOT_PATHS = ["/admin/login", "/wp-admin", "/admin/config", "/phpmyadmin"]

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl

  // 1. HONEYPOT TRAP: Immediate Ban/Block for bots
  if (HONEYPOT_PATHS.some(p => pathname.startsWith(p))) {
    return new NextResponse("Security Violation: Action Logged.", { status: 403 })
  }

  // 2. SECRET GATE LOGIC: Only allow access with the master token
  if (pathname === SECRET_GATE_PATH) {
    const token = req.nextUrl.searchParams.get("token")
    if (token === ACCESS_TOKEN) {
       return NextResponse.next()
    }
    // No token? Silent redirect to home
    return NextResponse.redirect(new URL("/", req.url))
  }

  // 3. ADMIN PROTECTION: Require Session
  if (pathname.startsWith("/admin")) {
    const session = await getToken({ req, secret: process.env.NEXTAUTH_SECRET })
    if (!session) {
      // Not logged in? Redirect to the gate
      return NextResponse.redirect(new URL(SECRET_GATE_PATH, req.url))
    }
  }

  return NextResponse.next()
}

export const config = {
  matcher: ["/admin/:path*", "/secret-gate", "/wp-admin", "/admin/login", "/phpmyadmin"],
}


