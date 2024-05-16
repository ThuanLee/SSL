FROM python:3.9.19-slim

# Create app directory
WORKDIR /app

# Install app dependencies
COPY requirements.txt .

RUN pip install -r requirements.txt

# Bundle app source
COPY . .

EXPOSE 8000

CMD ["python", "server.py"]