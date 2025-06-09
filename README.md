# NotSerp — Recycling Rewards Web App

**NotSerp** is a web platform that encourages recycling behavior through gamified incentives. Users can exchange recycled items for points, which can be redeemed for rewards such as vouchers.

---

## What is it?

An organisation that encourages the public to recycle by:
- Letting users earn points through QR scans on recycling bins
- Offering attractive vouchers in return
- Promoting sustainability via blog posts and community engagement

### Sub-Platforms:
- **Blog** — Promote awareness and share recycling news
- **Merch Store** — Spend earned vouchers on eco-merch
- **Rewards** — Earn points from recycling & redeem them

---

## Core Features

- Account Management & Points System (with recovery support)
- Role-Based Access Control (RBAC)
- Centralized Security System (*Sentinel*)
- Logging & Audit Trails
- Evidence Reconstruction System (for investigation)
- Product & Inventory Management
- Cart Management (with dynamic update post-payment)
- Blog Management
- Feedback Module
- Interactive Dashboards for Admins

---

##  Security Implementations

###  Access & Auth
- HTTPS
- RBAC with access control matrix
- Flask-Login session authentication
- 2FA (Two-Factor Authentication)
- Captcha (Bot Protection)
- Email-based account recovery with OTP
- Secure checkout with OTP timeout

###  Input & Upload Protection
- Cross-site scripting (XSS) & directory traversal detection
- CSRF protection (anti-CSRF tokens)
- File upload protection (Max 4MB, virus scan via Cloudmersive API)
- Strict file type validation (jpg/jpeg/png)

###  General Security Hardening
- Strong password policy (12+ chars, 1 upper, 1 lower, 1 digit, 1 symbol)
- Account lockout (5 failed attempts, 3-minute lock)
- Parameterized queries via SQLAlchemy
- Environment-based configuration
- Secure cookie flags (`Secure`, `HttpOnly`, `SameSite`)
- Strict Transport Security (HSTS)
- Static assets stored outside web root

---

##  Tech Stack

- **Frontend**: HTML, CSS, JS
- **Backend**: Flask (Python)
- **Database**: PostgreSQL
- **Security APIs**: Cloudmersive

---

