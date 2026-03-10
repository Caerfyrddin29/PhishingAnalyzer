@echo off
title PhishAnalyzer API Server
echo Starting PhishAnalyzer API Server...
echo Server will be available at: http://localhost:8000
echo API Documentation: http://localhost:8000/docs
echo.
echo Press Ctrl+C to stop the server
echo.

python api_server.py

pause
