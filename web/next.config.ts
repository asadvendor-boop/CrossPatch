import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  devIndicators: false,
  experimental: {
    globalNotFound: true,
  },
  async rewrites() {
    const developmentApiOrigin = process.env.CROSSPATCH_DEV_API_ORIGIN?.replace(/\/$/, "");
    if (process.env.NODE_ENV !== "development" || !developmentApiOrigin) return [];
    return [{
      source: "/api/:path*",
      destination: `${developmentApiOrigin}/api/:path*`,
    }];
  },
  turbopack: {
    root: path.resolve(__dirname, ".."),
  },
};

export default nextConfig;
