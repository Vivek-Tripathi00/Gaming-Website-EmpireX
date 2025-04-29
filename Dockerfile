# Use an official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy all files
COPY . .

# Upgrade pip
RUN python -m pip install --upgrade pip

# Install dependencies
RUN pip install -r requirements.txt

# Expose port
EXPOSE 5000

# Run your app
CMD ["python", "app.py"]
