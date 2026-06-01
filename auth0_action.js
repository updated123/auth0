/**
 * Auth0 Action — Post-Login Flow
 * =================================
 * Paste this into the Auth0 Dashboard:
 *   Actions → Library → Create Action → Post Login
 *
 * SETUP STEPS:
 * 1. Add secrets in the Action editor:
 *    - PLATFORM_WEBHOOK_URL  = https://your-domain.com/webhooks/idp-events
 *    - WEBHOOK_SECRET        = (same value as WEBHOOK_SECRET in your .env)
 *
 * 2. Add NPM dependency (Modules tab):
 *    - No extra modules needed — uses the built-in `crypto` module.
 *
 * 3. Deploy and attach to "Login / Post Login" flow trigger.
 *
 * WHAT THIS ACTION DOES:
 * - Fires on every successful Auth0 authentication (login or signup)
 * - Determines if it's a signup (first login) or a returning login
 * - POSTs the event to the platform webhook with an HMAC-SHA256 signature
 * - The platform backend verifies the signature before processing
 *
 * ARCHITECTURE NOTE:
 * - This action does NOT add custom claims to the JWT (by design)
 * - The JWT remains thin: sub, email, email_verified only
 * - All business context (roles, entitlements) is resolved server-side by the platform
 */

const crypto = require("crypto");

/**
 * Compute HMAC-SHA256 signature for the given payload.
 * Format: "sha256=<hex_digest>"
 */
function computeSignature(payload, secret) {
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(payload);
  return "sha256=" + hmac.digest("hex");
}

/**
 * Determine the event type based on Auth0 event metadata.
 *
 * Auth0 sets `event.stats.logins_count === 1` for the very first login,
 * which corresponds to a signup completion (the user has just accepted the
 * invitation or self-registered for the first time).
 */
function getEventType(event) {
  if (event.stats && event.stats.logins_count === 1) {
    return "user.signup_complete";
  }
  return "user.login";
}

/**
 * Build the webhook payload from Auth0 event data.
 *
 * Only thin, non-sensitive data is included.
 * We pass the Auth0 organisation ID so the platform can look up the
 * corresponding internal organisation record.
 */
function buildPayload(event, eventType) {
  const payload = {
    event_type: eventType,
    timestamp: new Date().toISOString(),
    user: {
      sub: event.user.user_id,
      email: event.user.email,
      email_verified: event.user.email_verified || false,
      // Name is informational only — not used for authz
      name: event.user.name || null,
    },
    // Auth0 organisation context (if user logged in through an org)
    auth0_org_id: event.organization ? event.organization.id : null,
    auth0_org_name: event.organization ? event.organization.name : null,
    // Request metadata for audit trail
    request: {
      ip: event.request ? event.request.ip : null,
      user_agent: event.request ? event.request.user_agent : null,
      method: event.request ? event.request.method : null,
    },
    // Connection type (social, enterprise, DB)
    connection: event.connection ? event.connection.name : null,
    connection_strategy: event.connection ? event.connection.strategy : null,
    // If the user was invited, Auth0 sets this
    invitation_id: event.user.invitation ? event.user.invitation.ticket_id : null,
  };

  // For signup events, include the role that was set at invitation time
  // (stored in app_metadata by the invite workflow or dashboard)
  if (eventType === "user.signup_complete" && event.user.app_metadata) {
    payload.role_requested = event.user.app_metadata.requested_role || null;
    payload.org_id = event.user.app_metadata.platform_org_id || null;
  }

  return payload;
}

/**
 * Main Action handler.
 *
 * The `api` object is provided by Auth0 and allows modifying the token,
 * denying access, etc. We intentionally do NOT add custom claims here —
 * the JWT stays thin by design.
 */
exports.onExecutePostLogin = async (event, api) => {
  const webhookUrl = event.secrets.PLATFORM_WEBHOOK_URL;
  const webhookSecret = event.secrets.WEBHOOK_SECRET;

  if (!webhookUrl || !webhookSecret) {
    console.error(
      "[auth0-action] Missing PLATFORM_WEBHOOK_URL or WEBHOOK_SECRET secret. Skipping webhook."
    );
    // Do not deny login — let the platform handle missing context gracefully
    return;
  }

  const eventType = getEventType(event);
  const payloadObj = buildPayload(event, eventType);
  const payloadStr = JSON.stringify(payloadObj);
  const signature = computeSignature(payloadStr, webhookSecret);

  console.log(`[auth0-action] Sending ${eventType} webhook for user: ${event.user.email}`);

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Auth0-Signature": signature,
        // Identify this sender for debugging
        "User-Agent": "Auth0-Action/1.0 (Post-Login)",
      },
      body: payloadStr,
      // Auth0 Actions have a 5-second limit for external HTTP calls
      // Set a timeout to avoid blocking the login flow
      signal: AbortSignal.timeout ? AbortSignal.timeout(4000) : undefined,
    });

    if (!response.ok) {
      const body = await response.text();
      console.warn(
        `[auth0-action] Platform webhook returned ${response.status}: ${body}`
      );
      // Non-200 from the platform should NOT block the login.
      // The platform can reconcile state later.
    } else {
      const result = await response.json();
      console.log(
        `[auth0-action] Webhook acknowledged: ${JSON.stringify(result)}`
      );
    }
  } catch (err) {
    // Network errors, timeouts, etc. must NOT block the login flow
    console.error(`[auth0-action] Webhook request failed: ${err.message}`);
  }

  // -----------------------------------------------------------------------
  // IMPORTANT: We do NOT call api.idTokenClaims.setCustomClaim() or
  // api.accessToken.setCustomClaim() for roles/entitlements here.
  //
  // This is the core architecture principle:
  //   IdP = authentication only (who are you?)
  //   Platform = authorisation context (what can you do?)
  //
  // Roles and entitlements are resolved by the platform backend after
  // token validation, using the `sub` as a lookup key into the platform DB.
  // -----------------------------------------------------------------------
};

/**
 * Optional: Post-User-Registration trigger
 * ==========================================
 * If you need to handle user.invited events (when an admin creates a user
 * directly in Auth0 rather than via the invitation API), attach this to
 * the "Post User Registration" trigger as well.
 *
 * exports.onExecutePostUserRegistration = async (event) => {
 *   // Same webhook call pattern as above with event_type = "user.signup_complete"
 * };
 */
