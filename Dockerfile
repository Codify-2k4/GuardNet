# Use official lightweight Python image
FROM python:3.9-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code
COPY src/ ./src/
<<<<<<< HEAD
COPY data/ ./data/
=======
>>>>>>> 5dbcbb5 (First commit)

# Set Python path so modules can be imported
ENV PYTHONPATH=/app

# Train the base model during build (so container starts ready)

# Expose port for Flask
EXPOSE 5000

# Run the app
CMD ["python", "src/app/app.py"]