FROM python:3.12-slim

WORKDIR /app

RUN pip install uv

COPY requirements.txt .
RUN uv pip install --system -r requirements.txt

COPY . .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
