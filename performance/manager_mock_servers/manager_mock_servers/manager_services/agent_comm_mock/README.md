# Server Manager
curl -X POST https://127.0.0.1:55000/authentication -H "Content-Type: application/json" -d '{"user":"testing", "password": "fdsa"}' -k


curl -X POST https://127.0.0.1:55000/agents -H "Content-Type: application/json"  -H "Authorization: Bearer $TOKEN" -d '{"uuid":"98e0c02d-a632-4d13-90f4-1a16aba915a6", "key":"mykey", "name":"testing1"}' -k

# --------------


curl -X POST https://127.0.0.1:2700/authentication -H "Content-Type: application/json" -d '{"uuid":"98e0c02d-a632-4d13-90f4-1B16aba915a6", "key": "testing2"}' -k

curl -X POST "https://127.0.0.1:2700/events/stateless" -H "Authorization: Bearer $TOKEN"  -H "Content-Type: application/json"  -d '{
    "events": [
        {
            "id": 1,
            "data": "DATA"
        },
        {
            "id": 2,
            "data": "DATA"
        }
    ]
}' -k
