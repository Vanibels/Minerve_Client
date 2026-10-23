From python:3.9-slim
Workdir /app
Copy requirements.txt .
run pip install --no-cache-dir -r requirements.txt
Copy . .
expose 3467
CMD ["python", "src/agent.py"]