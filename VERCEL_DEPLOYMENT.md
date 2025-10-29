# GapoTravels Vercel Deployment Guide

## Prerequisites
- Vercel account (https://vercel.com)
- GitHub account with your repository
- Environment variables configured

## Deployment Steps

### 1. **Push to GitHub**
```bash
git add .
git commit -m "Prepare for Vercel deployment"
git push origin main
```

### 2. **Deploy to Vercel**
- Go to https://vercel.com/new
- Connect your GitHub repository
- Select your repo `GapoTravels`

### 3. **Configure Environment Variables**
In the Vercel deployment settings, add these environment variables:
```
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_key
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
MAILJET_API_KEY=your_mailjet_api_key
MAILJET_SECRET_KEY=your_mailjet_secret_key
MAILJET_TEMPLATE_ID_VERIFY=verify_template_id
MAILJET_TEMPLATE_ID_RESET=reset_template_id
MAILJET_FROM_EMAIL=your_email@example.com
MAILJET_FROM_NAME=GapoTravels
FLASK_SECRET_KEY=generate_a_random_secret_key
```

### 4. **Update Callback URLs**
Update these in your Google OAuth and Supabase settings:
```
Callback URL: https://your-vercel-domain.vercel.app/callback/google
Auth Callback: https://your-vercel-domain.vercel.app/auth-callback/login
```

### 5. **Deploy**
Click "Deploy" and wait for the build to complete.

## Important Notes
- Vercel has a 10-second execution timeout for serverless functions
- Long-running operations may timeout
- Static files should be optimized
- Database connections should be pooled

## Troubleshooting
- Check Vercel logs in the dashboard
- Verify all environment variables are set
- Ensure Supabase URLs and keys are correct
- Check CORS settings if getting connection errors

## Alternative: Keep Using Render
Your app is already optimized for Render.com, which fully supports Flask. Consider:
- Render provides 750 free hours per month
- Better performance for long-running requests
- No serverless function timeout limits
