import type { Request, Response, NextFunction } from "express";

interface BlockedIP {
  ip: string;
  blockedUntil: number;
  reason: string;
}

class IPBlocker {
  private blockedIPs: Map<string, BlockedIP> = new Map();
  private readonly BLOCK_DURATION = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
  private readonly MAX_REQUESTS = 70; // Maximum requests per window
  private readonly WINDOW_MS = 60 * 1000; // 1 minute window
  private requestCounts: Map<string, { count: number; resetTime: number }> =
    new Map();

  private isIPBlocked(ip: string): boolean {
    const blockedIP = this.blockedIPs.get(ip);
    if (!blockedIP) return false;

    if (Date.now() > blockedIP.blockedUntil) {
      this.blockedIPs.delete(ip);
      return false;
    }

    return true;
  }

  private trackRequest(ip: string): boolean {
    const now = Date.now();
    const requestData = this.requestCounts.get(ip);

    if (!requestData || now > requestData.resetTime) {
      this.requestCounts.set(ip, { count: 1, resetTime: now + this.WINDOW_MS });
      return true;
    }

    requestData.count++;
    if (requestData.count > this.MAX_REQUESTS) {
      this.blockIP(ip, "Too many requests");
      return false;
    }

    return true;
  }

  public blockIP(ip: string, reason: string): void {
    this.blockedIPs.set(ip, {
      ip,
      blockedUntil: Date.now() + this.BLOCK_DURATION,
      reason,
    });
  }

  public getBlockedIPs(): BlockedIP[] {
    const now = Date.now();
    return Array.from(this.blockedIPs.values()).filter(
      (blockedIP) => now <= blockedIP.blockedUntil,
    );
  }

  public middleware = (
    req: Request,
    res: Response,
    next: NextFunction,
  ): void => {
    const ip = req.ip || req.socket.remoteAddress || "unknown";

    if (this.isIPBlocked(ip)) {
      const blockedIP = this.blockedIPs.get(ip);
      res.status(403).json({
        error: "IP Blocked",
        message: `Your IP has been blocked. Reason: ${blockedIP?.reason}`,
        blockedUntil: new Date(blockedIP?.blockedUntil || 0).toISOString(),
      });
      return;
    }

    if (!this.trackRequest(ip)) {
      res.status(429).json({
        error: "Too Many Requests",
        message: "Your IP has been blocked due to suspicious activity",
      });
      return;
    }

    next();
  };
}

// Create a singleton instance
const ipBlocker = new IPBlocker();

export default ipBlocker;
