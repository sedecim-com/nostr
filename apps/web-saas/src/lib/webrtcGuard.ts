/**
 * SEC-05: the web client never uses WebRTC, and an RTCPeerConnection gathers ICE candidates (local
 * addresses, mDNS names, STUN-reflected public IP) without any permission prompt. Removing the
 * constructors before the app runs means no code in this page (a dependency, an injected script)
 * can open one, whatever the profile. Imported first by main.tsx; verified by tests/browser/web-leaks.e2e.ts.
 *
 * Limit: a same-origin iframe created by script gets fresh globals; script-src 'self' (CSP) is what keeps
 * foreign script out of the page in the first place.
 */
export const WEBRTC_GLOBALS = [
  'RTCPeerConnection',
  'webkitRTCPeerConnection',
  'mozRTCPeerConnection',
  'RTCDataChannel',
  'RTCIceCandidate',
  'RTCIceTransport',
  'RTCSessionDescription',
  'RTCRtpSender',
  'RTCRtpReceiver',
  'RTCRtpTransceiver',
  'RTCSctpTransport',
  'RTCDtlsTransport',
] as const;

export function disableWebRtc(target: object = globalThis): void {
  for (const name of WEBRTC_GLOBALS) {
    if (!(name in target)) continue;
    try {
      Object.defineProperty(target, name, { value: undefined, writable: false, configurable: false, enumerable: false });
    } catch {
      /* non-configurable in this engine: leave it, the E2E test would flag it */
    }
  }
}

disableWebRtc();
