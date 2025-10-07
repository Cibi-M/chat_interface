#!/bin/bash
# start.sh - Script to start the application on Render

uvicorn main:app --host 0.0.0.0 --port $PORT