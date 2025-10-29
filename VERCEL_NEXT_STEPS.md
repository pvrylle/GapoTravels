# Vercel Deployment - Next Steps

## ✅ Deployment Complete!
Your app is now deployed at: **https://gapotravels-odu0iarb3-rylles-projects.vercel.app**

## ⚠️ IMPORTANT: Add Environment Variables

Your app is deployed but will not work until you add environment variables. Run these commands:

```powershell
# Set each environment variable for production
vercel env add SUPABASE_URL
vercel env add SUPABASE_KEY
vercel env add SUPABASE_SERVICE_ROLE_KEY
vercel env add GOOGLE_CLIENT_ID
vercel env add GOOGLE_CLIENT_SECRET
vercel env add MAILJET_API_KEY
vercel env add MAILJET_SECRET_KEY
vercel env add MAILJET_TEMPLATE_ID_VERIFY
vercel env add MAILJET_TEMPLATE_ID_RESET
vercel env add MAILJET_FROM_EMAIL
vercel env add MAILJET_FROM_NAME
vercel env add FLASK_SECRET_KEY
```

## Or Add via Vercel Dashboard

1. Go to: https://vercel.com/rylles-projects/gapotravels
2. Click "Settings" tab
3. Click "Environment Variables"
4. Add all the variables above with their values

## Required Environment Variables

```
SUPABASE_URL = Your Supabase project URL
SUPABASE_KEY = Your Supabase anonymous key
SUPABASE_SERVICE_ROLE_KEY = Your Supabase service role key
GOOGLE_CLIENT_ID = Your Google OAuth Client ID
GOOGLE_CLIENT_SECRET = Your Google OAuth Client Secret
MAILJET_API_KEY = Your Mailjet API key
MAILJET_SECRET_KEY = Your Mailjet secret key
MAILJET_TEMPLATE_ID_VERIFY = Email verification template ID (number)
MAILJET_TEMPLATE_ID_RESET = Password reset template ID (number)
MAILJET_FROM_EMAIL = Your Mailjet sender email
MAILJET_FROM_NAME = GapoTravels
FLASK_SECRET_KEY = Generate with: python -c "import secrets; print(secrets.token_hex(32))"
```

## After Adding Variables

Redeploy with:
```powershell
cd e:\GapoTravels
vercel --prod
```

## Update OAuth Callback URLs

Update these in your Google and Supabase settings:

```
Google OAuth Redirect URI:
https://gapotravels-odu0iarb3-rylles-projects.vercel.app/callback/google

Supabase Auth Callback:
https://gapotravels-odu0iarb3-rylles-projects.vercel.app/auth-callback/login
```

## Check Deployment Status

View logs and status:
```powershell
vercel logs
vercel status
```
