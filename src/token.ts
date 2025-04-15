import { DurableObject } from "cloudflare:workers";
import { Env } from "./types";

export class Token extends DurableObject {
  private state: DurableObjectState;
  protected declare env: Env;
  private storage: DurableObjectStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.state = state;
    this.env = env;
    this.storage = this.state.storage
  }

  async setRelay(relayId: string) {
    return await this.storage.put('relayId', relayId)
  }

  async getRelay(): Promise<string | null> {
    return await this.storage.get('relayId')
  }

  async delete() {
    return await this.storage.deleteAll()
  }
}
