# Production deployment A-to-Z guide

This project is structured for a real public launch using:
- Vercel for the storefront and admin frontend
- Render for the Node/Express API backend
- Supabase for Postgres data, auth, and admin-friendly persistence

This file is the complete checklist of what to do, what to add, and what to configure before the site goes live.

## Security and commercial launch rules

- Keep the repository private for client work unless the customer explicitly wants a public license.
- Never commit `.env`, database dumps, PII, payment credentials, or customer data.
- Treat the browser as a UI only; the server and database are the source of truth for orders, pricing, stock, and payment state.
- Protect admin APIs and require server-side authorization.
- Push production configuration to environment managers such as Vercel or Render, not to Git.
- Do not classify customer data, order integrity, inventory, authentication, or payment verification as acceptable risk without explicit customer approval.

## 1. Production setup overview

Use this target architecture:
- Frontend: https://www.yourbrand.com
- Frontend redirect: https://yourbrand.com
- API: https://api.yourbrand.com
- Database: Supabase Postgres
- Repo: GitHub public or private repository
- Security: HTTPS, secret env values, strict CORS, protected admin routes

## 2. Quick admin login + deployment map

### Default local admin access (development only)

This project is set up so a local demo admin can log in with:

- Email: `admin@example.com`
- Password: `ChangeMe123!`

Important:
- This is only for local testing and demo work.
- For production, replace it with your own strong secret values before launch.
- Do not keep the development password in GitHub, Render, Vercel, or any hosting dashboard.

### What software to use and where to upload files

Use this setup for a working commercial deployment:

- Web app / backend: Node.js + Express server in this repo
- Database: PostgreSQL (recommended for production) or SQLite only for local/dev testing
- Hosting for backend: Render, Railway, DigitalOcean App Platform, VPS with PM2, or a managed Node host
- Hosting for frontend if separate: Vercel or static hosting only if you split frontend and backend
- File upload location: upload the project root files to the backend host, not just the static HTML folder

Recommended deployment pattern for this repo:

1. Upload the entire repository to the backend host.
2. Install dependencies with `npm install`.
3. Configure `.env` values on the host.
4. Run `npm run migrate`.
5. Start with `npm start`.
6. Open the admin login page at `/admin-login.html`.

If you use a separate static frontend host:

- The backend must still run on a Node server.
- The frontend should only talk to the API domain, not directly to local files.
- Do not upload only the `index.html` file to a static host when the admin login and protected API are needed.

### Required settings to add before launch

Set these values in the hosting environment manager:

```env
PORT=10000
NODE_ENV=production
SESSION_SECRET=replace_with_a_long_random_secret
ADMIN_PIN=replace_with_a_strong_admin_pin
ADMIN_EMAIL=admin@yourcompany.com
ADMIN_PASSWORD=replace_with_a_strong_password
ADMIN_PASSWORD_SALT=replace_with_a_long_random_salt
DATABASE_URL=postgresql://user:password@host:5432/database
ALLOWED_ORIGINS=https://www.yourbrand.com,https://yourbrand.com,https://api.yourbrand.com
```

### Production rule

- Change the admin email/password before going live.
- Keep the credentials in the host environment manager, not in the repository.
- Never expose the admin credentials in screenshots, support notes, or public folders.

## 2. Copy-paste deployment runbook

Use this exact order for the live deployment:

1. Create GitHub repo and push code.
2. Create Vercel project and connect GitHub.
3. Add frontend env vars in Vercel.
4. Add custom domains for www.yourbrand.com and yourbrand.com.
5. Configure DNS and enable HTTPS.
6. Create Render web service and connect GitHub.
7. Add backend env vars in Render.
8. Add custom domain api.yourbrand.com.
9. Create Supabase project and Postgres DB.
10. Copy Supabase URL and keys into env values.
11. Create tables for products, categories, orders, bills, hero_slides, discount_codes.
12. Add RLS/admin policies.
13. Set DATABASE_URL in Render from Supabase.
14. Add CORS allowlist with exact production domains.
15. Add admin session secret and admin PIN.
16. Seed real categories, products, and site content.
17. Test login, CRUD, orders, payments, and product images.
18. Verify HTTPS, cookies, and redirects.
19. Check SEO and sitemap/robots.
20. Launch, then monitor for errors and downtime for the first 7 days.

## 3. What to add before launch

Add the following items:
- Real domain names
- Vercel account and project
- Render account and web service
- Supabase project and database
- Production env values in all providers
- Real admin credentials and session secret
- Real API URL configuration in the frontend
- Actual product/category data
- Final SEO, robots, sitemap, and metadata
- SSL certificate and domain verification
- Monitoring, alerts, and backup plan

## 4. A-to-Z production checklist

### A. Acquire accounts
- Create a GitHub repository for the project.
- Create a Vercel account.
- Create a Render account.
- Create a Supabase account.
- Buy or confirm the production domains.
- Set up your admin email and recovery options.

### B. Buy and verify domains
- Choose the main domain: yourbrand.com
- Add www subdomain and API subdomain.
- Configure DNS records in your registrar.
- Verify apex + www + api domain ownership with Vercel and Render.
- Enable automatic SSL.

### C. Connect GitHub
- Push the project to GitHub.
- Keep secrets out of Git.
- Do not commit .env files, database dumps, or private keys.
- Use GitHub branch protection for production deploys.

### D. Create the Vercel project
- Import the GitHub repo in Vercel.
- Set root directory to the project root.
- Use the app as a static/public frontend deploy.
- Add environment variables in Vercel.
- Add custom domains for the storefront.
- Confirm HTTPS is active.

### E. Create the Render service
- Create a new Web Service on Render.
- Connect the same GitHub repository.
- Set build command to: npm install
- Set start command to: npm start
- Add backend env variables in Render.
- Add custom domain: api.yourbrand.com
- Enable auto SSL.

### F. Create the Supabase project
- New project in Supabase.
- Copy the project URL and keys.
- Create a Postgres database.
- Get the direct database connection string.
- Add tables for products, categories, hero_slides, orders, discount_codes, bills.
- Add basic indexes for faster admin queries.
- Set up RLS policies for admin-only writes.

### G. Set production env values

#### Backend / Render env
```env
PORT=10000
NODE_ENV=production
SESSION_SECRET=replace-with-a-long-random-secret
ADMIN_PIN=replace-with-a-strong-admin-pin
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@db.YOUR_PROJECT_REF.supabase.co:5432/postgres
FRONTEND_URL=https://www.yourbrand.com
BACKEND_URL=https://api.yourbrand.com
CORS_ORIGIN=https://www.yourbrand.com,https://yourbrand.com,https://api.yourbrand.com
ALLOWED_ORIGINS=https://www.yourbrand.com,https://yourbrand.com,https://api.yourbrand.com
SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
SUPABASE_ANON_KEY=YOUR_SUPABASE_ANON_KEY
SUPABASE_SERVICE_ROLE_KEY=YOUR_SUPABASE_SERVICE_ROLE_KEY
GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET=YOUR_GOOGLE_CLIENT_SECRET
```

#### Frontend / Vercel env
```env
NEXT_PUBLIC_FRONTEND_URL=https://www.yourbrand.com
NEXT_PUBLIC_API_URL=https://api.yourbrand.com
NEXT_PUBLIC_SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=YOUR_SUPABASE_ANON_KEY
```

### H. Hardening and security
- Keep secrets in provider env managers only.
- Never commit .env or local DB files.
- Use HTTPS only.
- Validate all inputs on the server.
- Reject unsafe payloads and script injection attempts.
- Restrict admin routes to authenticated server sessions.
- Use a strict allowed-origin CORS list.
- Set security headers in Express.
- Keep admin login rate-limited.
- Disable default server fingerprinting when possible.

### I. Admin access setup
- Set a strong admin session secret.
- Use a secure admin PIN or real auth provider.
- Only allow admin access from approved domains.
- Set the admin login page to be protected and not public by default.
- Restrict create/edit/delete routes to authenticated admin users.
- Log admin access and failed login attempts.

### J. Database schema
Create tables such as:
- products
- categories
- hero_slides
- orders
- bills
- discount_codes
- customers
- reviews
- payments

Keep each table minimal and production-friendly.
Only store the data you actually need for commerce operations.

### K. Category and product data
- Pre-save your real categories.
- Keep category names consistent across storefront and admin.
- Add product SKUs, price, stock, status, and images.
- Keep the categories list loaded from a trusted source.
- Do not leave placeholder or mock catalog data in production.

### L. Order and payment flow
- Accept orders with proper status tracking.
- Keep order states: pending, payment verification, confirmed, processing, shipped, delivered, cancelled.
- For bank transfer orders, require customer reference details and verification.
- Store only minimum payment metadata required by the business.
- Do not expose sensitive bank data to customers or the frontend.

### M. Monitoring and logs
- Enable Render and Vercel deployment logs.
- Monitor API errors and failed admin logins.
- Check product CRUD and order actions after each deploy.
- Create a basic alert for backend downtime.

### N. SEO and public launch checks
- Add real metadata, title, description, social tags.
- Confirm robots.txt and sitemap.xml are valid.
- Add canonical URLs.
- Include Open Graph and Twitter tags.
- Confirm product pages have unique titles and descriptions.

### O. Performance
- Keep frontend assets compressed and lightweight.
- Optimize images before upload.
- Reduce script and style bloat.
- Avoid unnecessary third-party JS.
- Use efficient queries and proper indexing in Supabase/Postgres.

### P. Privacy and legal
- Add Privacy Policy page.
- Add Terms page.
- Add Refunds / Returns page.
- Add Shipping page.
- Add Contact page.
- Add Cookies notice if needed.
- Confirm data retention and customer privacy policy.

### Q. Quality assurance before go-live
- Test homepage, category pages, product pages, checkout, profile, and admin login.
- Test all CRUD actions in admin.
- Test order creation and order status updates.
- Test server responses for invalid input.
- Test login failure handling.
- Test CORS on production URLs.
- Test with real domain URLs, not localhost.

### R. Redirects and routing
- Ensure www and non-www domains resolve correctly.
- Add redirect rules where needed.
- Keep storefront and API on separate domains.
- Do not expose internal server routes publicly.

### S. SSL and security verification
- Confirm the frontend has HTTPS active.
- Confirm the API has HTTPS active.
- Confirm secure cookies and same-site settings are correct.
- Verify CSP and X-Frame-Options behave as expected.
- Validate admin session cookies are not exposed.

### T. Trust and user protection
- Add protection against XSS and unsafe URL values.
- Strip unsafe HTML and script-like strings from form data.
- Sanitize and validate all user-submitted data.
- Restrict admin actions to trusted sessions.
- Keep customer-facing routes separate from internal admin routes.

### U. Users and permissions
- Define admin roles:
  - Super Admin
  - Manager
  - Order Manager
  - Inventory Manager
- Use least-privilege access.
- Only managers with actual responsibilities should access sensitive modules.

### V. Vulnerability review
- Check for exposed secrets in Git history.
- Review API route exposure.
- Verify no admin session data is stored in client-side storage.
- Confirm all credential values live only in environment variables.

### W. Webhooks and integrations
- If using email, WhatsApp, notifications, or third-party services, store provider credentials in env vars only.
- Add webhook validation if used.
- Keep webhook secret checks in place.

### X. XML and app metadata
- Confirm robots.txt is live and correct.
- Confirm sitemap.xml is generated and valid.
- Confirm manifest.webmanifest is set to the production domain.
- Add Open Graph images and correct canonical URLs.

### Y. Yes, monitor after launch
- Watch uptime, errors, failed requests, and slow endpoints.
- Review the first 7 days of live traffic.
- Fix broken links, failed admin actions, and user-reported issues.
- Keep a rollback plan ready.

### Z. Zero-risk launch plan
Before going public, do this:
- Confirm all env vars are filled correctly.
- Confirm API URL points to the live Render domain.
- Confirm CORS allows only the production domains.
- Confirm admin auth works in production.
- Confirm product/category data is not mock data.
- Confirm product images load from the live domain.
- Confirm orders can be created and managed.
- Confirm admin dashboard functions work with real data.
- Confirm HTTPS is active on every live domain.
- Confirm nothing private is in the Git repo.
- Confirm backup, monitoring, and rollback steps exist.

## 5. Final production launch command list

Use this as the final order of work:
1. Set up GitHub.
2. Set up Vercel.
3. Set up Render.
4. Set up Supabase.
5. Fill all real env values.
6. Add production domains.
7. Configure DNS and SSL.
8. Add CORS allowlist.
9. Add admin secrets.
10. Create DB tables and policies.
11. Seed categories and products.
12. Test admin login.
13. Test order flow and payment verification.
14. Test storefront navigation and SEO metadata.
15. Launch publicly.
16. Monitor for the first 7 days.

## 6. Production safety summary

This project is already stronger than a simple mockup because it includes:
- server-side admin session protection
- hardened security headers
- input validation and sanitizer checks
- CORS restrictions
- protected admin routes
- product and category structure
- storefront + admin split

However, the final public production launch still requires:
- real cloud credentials
- actual production domains
- live Supabase DB connection
- final category and catalog data
- real admin access configuration
- production monitoring and verified launch checks

## 7. Recommended final production pattern

Use this pattern for the live site:
- Vercel: frontend and admin dashboard
- Render: API and admin session endpoints
- Supabase: database and data access layer
- GitHub: code repository
- DNS: domain + SSL provider

This setup is clean, scalable, and production-appropriate for a public storefront.

## 8. Final note

Do not push real secrets into GitHub. Use each provider's environment settings.
Never rely on browser-only storage as the live commerce source of truth.
The site should use server-side logic and a real database before public commerce operations.
