import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Proxy API to FastAPI so the browser calls same-origin /api/... (avoids CORS in dev).
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://127.0.0.1:3001/:path*",
      },
    ];
  },
};

export default nextConfig;
