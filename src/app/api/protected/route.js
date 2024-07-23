import jwt from "jsonwebtoken";
import { NextResponse } from "next/server";
import { headers } from "next/headers";

export async function GET() {
  try {
    const headersInstance = headers();
    const authHeader = headersInstance.get("authorization");

    if (!authHeader) {
      return NextResponse.json({ message: "Authorization header missing" }, { status: 400 });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return NextResponse.json({ message: "Token missing" }, { status: 400 });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      return NextResponse.json({ message: "Token verification failed" }, { status: 400 });
    }

    if (decoded.exp < Math.floor(Date.now() / 1000)) {
      return NextResponse.json({ message: "Token expired" }, { status: 400 });
    }

    return NextResponse.json({ data: "Protected data" }, { status: 200 });

  } catch (error) {
    console.error("Token verification failed", error);
    let message = "Unauthorized";
    if (error.name === "JsonWebTokenError") {
      message = "Invalid token";
    } else if (error.name === "TokenExpiredError") {
      message = "Token expired";
    }
    return NextResponse.json({ message }, { status: 400 });
  }
}