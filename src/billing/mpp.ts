/**
 * Machine Payments Protocol (MPP) adapter — settlement for on-demand credits.
 *
 * MPP (https://mpp.dev) is an open HTTP-402 standard for machine-to-machine
 * payments: a resource server issues a **Challenge**, the client presents a
 * **Credential**, and settlement produces a **Receipt** — no API keys or signup.
 * It supports three payment models:
 *
 *   - `pay-per-request`  — settle each on-demand charge immediately.
 *   - `session`          — accrue metered usage against an off-chain voucher and
 *                          settle the net periodically (near-zero per-request fee).
 *   - `subscription`     — a recurring fixed payment that refills system credits.
 *
 * ARES uses MPP to settle **on-demand** (pay-as-you-go) usage once a prepaid
 * balance is exhausted. This module defines the protocol shapes and a hermetic
 * `LocalMppClient` default; a real HTTP-402 client attaches via `MppClient`
 * behind config (`MPP_ENDPOINT`), off by default like the CUA analyzer.
 */
import { v4 as uuidv4 } from "uuid";

import { log } from "../config/logger.js";

export type MppPaymentModel = "pay-per-request" | "session" | "subscription";

/** HTTP-402 challenge: "pay this much to access this resource". */
export interface MppChallenge {
  /** Logical resource being paid for (e.g. an audit thread id). */
  resource: string;
  amountUsd: number;
  model: MppPaymentModel;
  /** Server-generated anti-replay nonce. */
  nonce: string;
}

/** Client-presented payment credential answering a challenge. */
export interface MppCredential {
  challengeNonce: string;
  payerId: string;
  /** Opaque payment token / voucher (bearer, per MPP). */
  token: string;
}

/** Settlement receipt. */
export interface MppReceipt {
  receiptId: string;
  resource: string;
  amountUsd: number;
  model: MppPaymentModel;
  settledAt: number;
  payerId: string;
}

/** A settlement backend. Real implementations speak HTTP-402 to an MPP server. */
export interface MppClient {
  /** Verify a credential against a challenge and settle, returning a receipt. */
  settle(challenge: MppChallenge, credential: MppCredential): Promise<MppReceipt>;
}

/** Mint a challenge for an amount owed on a resource. */
export function createChallenge(
  resource: string,
  amountUsd: number,
  model: MppPaymentModel = "pay-per-request",
): MppChallenge {
  return { resource, amountUsd, model, nonce: uuidv4() };
}

/**
 * Hermetic, in-process settlement — the default. Records receipts locally and
 * always succeeds; used when no real MPP endpoint is configured, so audits run
 * fully offline. Mirrors how `session` vouchers net out, minus the chain.
 */
export class LocalMppClient implements MppClient {
  private readonly receipts: MppReceipt[] = [];

  async settle(
    challenge: MppChallenge,
    credential: MppCredential,
  ): Promise<MppReceipt> {
    if (credential.challengeNonce !== challenge.nonce) {
      throw new Error("MPP credential does not match challenge nonce");
    }
    const receipt: MppReceipt = {
      receiptId: uuidv4(),
      resource: challenge.resource,
      amountUsd: challenge.amountUsd,
      model: challenge.model,
      settledAt: Date.now(),
      payerId: credential.payerId,
    };
    this.receipts.push(receipt);
    log.debug("MPP settled locally", {
      component: "billing.mpp",
      receiptId: receipt.receiptId,
      amountUsd: receipt.amountUsd,
      model: receipt.model,
    });
    return receipt;
  }

  /** All receipts settled by this client (for reporting/tests). */
  history(): readonly MppReceipt[] {
    return [...this.receipts];
  }
}

export interface MppConfig {
  /** Real HTTP-402 endpoint. When unset, settlement is local/hermetic. */
  endpoint?: string;
  payerId: string;
}

/**
 * Select a settlement client. Returns the hermetic `LocalMppClient` unless a
 * real `endpoint` is configured. A production HTTP-402 client would be
 * constructed here (kept out of the default path so the agent stays offline).
 */
export function createMppClient(config: MppConfig): MppClient {
  if (config.endpoint) {
    // A real implementation performs the HTTP-402 Challenge→Credential→Receipt
    // handshake against `config.endpoint`. Left unwired so default runs and the
    // test suite make no network calls; falls back to local settlement.
    log.warn(
      { component: "billing.mpp", endpoint: config.endpoint },
      "MPP_ENDPOINT set but the HTTP-402 client is not wired; settling locally",
    );
  }
  return new LocalMppClient();
}
