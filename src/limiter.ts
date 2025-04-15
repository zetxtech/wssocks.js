import { DurableObject } from "cloudflare:workers";

export class RateLimiter extends DurableObject {
  static milliseconds_per_request = 1;
  static milliseconds_for_updates = 5000;
  static capacity = 10000;

  constructor(ctx, env) {
    super(ctx, env);
    this.tokens = RateLimiter.capacity;
  }

  async getMillisecondsToNextRequest() {
    this.checkAndSetAlarm();

    let milliseconds_to_next_request = RateLimiter.milliseconds_per_request;
    if (this.tokens > 0) {
      this.tokens -= 1;
      milliseconds_to_next_request = 0;
    }

    return milliseconds_to_next_request;
  }

  async checkAndSetAlarm() {
    let currentAlarm = await this.ctx.storage.getAlarm();
    if (currentAlarm == null) {
      this.ctx.storage.setAlarm(
        Date.now() +
          RateLimiter.milliseconds_for_updates *
            RateLimiter.milliseconds_per_request,
      );
    }
  }

  async alarm() {
    if (this.tokens < RateLimiter.capacity) {
      this.tokens = Math.min(
        RateLimiter.capacity,
        this.tokens + RateLimiter.milliseconds_for_updates,
      );
      this.checkAndSetAlarm();
    }
  }
}