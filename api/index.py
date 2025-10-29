"""
API wrapper for Vercel serverless functions
This exports the Flask app as a handler for Vercel
"""
import sys
from app import app

# Export the Flask app instance for Vercel
export = app

# For Vercel Functions, we need to return the WSGI application
__all__ = ['export']
