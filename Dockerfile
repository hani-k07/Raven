FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for some python packages
RUN apt-get update && apt-get install -y     build-essential     libssl-dev     libffi-dev     python3-dev     && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Start the application
CMD ["python", "run.py"]
