FROM python:3.12

WORKDIR /app

COPY service_account_api/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY service_account_api /app/service_account_api

CMD ["uvicorn", "service_account_api.main:app", "--host", "0.0.0.0", "--port", "8000"]