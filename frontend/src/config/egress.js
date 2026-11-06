// Fortexa's outbound (egress) public IP: every scan request to a customer's site
// leaves AWS through one NAT gateway with this Elastic IP, so it is the address a
// customer with IP restrictions must allowlist.
//
// Verified 2026-11-06: the backend, both ZAP services and WebCheck run in the
// private subnets whose default route is nat-02a1767ec21550739, Elastic IP
// 54.178.209.53 (fortexa-eip-ap-northeast-1a). If the NAT gateway or its Elastic IP
// changes, set REACT_APP_FORTEXA_EGRESS_IP at build time (CI/CD) — no code change.
export const FORTEXA_EGRESS_IP = process.env.REACT_APP_FORTEXA_EGRESS_IP || '54.178.209.53';
